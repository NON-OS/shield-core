// NONOS Operating System (AGPL-3.0-or-later)
//! Emit an outer artifact through the preprocessed-periodic prover.
//!
//! The periodic columns commit to their own Merkle root and their claims at
//! z travel in a sidecar opened against that root at every query, so the
//! verifier computes the composition from proof bytes alone against a root
//! baked in at deployment; a value handed to a verifier rather than derived
//! is a value an adversary chooses.
//!
//! Which outer is proved comes from the point selector. The periodic tree is
//! a constant of the circuit and is kept in `.treecache` under its root's
//! name; `root=<hex>` names the tree to load and the root the proof must
//! verify against, and a tree that is not this circuit's is refused before
//! anything is baked. The bytes are read back and verified from disk rather
//! than from the value in memory, because a proof that only verifies in the
//! process that produced it has not been shown to travel.

use stark_proofs::crypto::stark::air::replay_pre::replay_comp_z_pre;
use stark_proofs::crypto::stark::air::{stark_prove_ext_rounds, stark_verify_ext_rounds_why, Air};
use stark_proofs::crypto::stark::merkle::DIGEST_BYTES;
use stark_proofs::proof_wire::{serialize_rounds, ParamSet};
use stark_proofs::recursion_assembly::point::Point;
use stark_proofs::recursion_assembly::{assemble, Tamper};
use stark_proofs::shield_params::inner as inner_point;
use stark_proofs::shield_params::rehearsal::dev;
use stark_proofs::tree_cache;
use std::time::Instant;

mod publics;
use publics::pool_intents;

/// A digest's worth of lower case hex characters, or nothing. A root of any
/// other shape is a typo, and a typo baked into a verifier is a verifier for
/// no proof.
fn well_formed_root(hex: &str) -> Option<String> {
    let hex = hex.trim().to_ascii_lowercase();
    if hex.len() != 2 * DIGEST_BYTES || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(hex)
}

fn hex_of(root: &[u8; 32]) -> String {
    root[..DIGEST_BYTES]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let point = Point::from_args(&args);
    let real = args.iter().any(|a| a == "real") || point != Point::Settlement;
    // The inner point unless the development point is asked for by name, so a
    // forgotten flag never yields a weak artifact.
    let dev_params = args.iter().any(|a| a == "dev");
    let supplied = args.iter().find_map(|a| a.strip_prefix("root="));
    /*
     * The output path is the first argument that is not a flag, so every flag
     * has to be named here or it becomes the filename.
     */
    let out = args
        .iter()
        .find(|a| {
            !Point::is_flag(a)
                && a.as_str() != "real"
                && a.as_str() != "deployment"
                && a.as_str() != "dev"
                && !a.starts_with("root=")
        })
        .cloned()
        .unwrap_or_else(|| format!("{}-pre.proof", point.name()));

    let expected_root = match supplied {
        Some(hex) => match well_formed_root(hex) {
            Some(hex) => Some(hex),
            None => {
                eprintln!("root= wants 64 hex characters; refusing to bake {hex:?}");
                std::process::exit(2);
            }
        },
        None => None,
    };

    let (n_queries, grind_bits, extra_blowup) = if dev_params {
        eprintln!("development parameters: this artifact is not a deployment one");
        (dev::N_QUERIES, dev::GRIND_BITS, dev::EXTRA_BLOWUP_BITS)
    } else {
        (
            inner_point::N_QUERIES,
            inner_point::GRIND_BITS,
            inner_point::EXTRA_BLOWUP_BITS,
        )
    };
    println!(
        "point     {} over an inner at {} queries, extra blowup {}",
        point.name(),
        point.inner_queries(),
        point.inner_extra()
    );
    println!(
        "params    {} queries, {} grind bits, extra blowup {} (rate 1/{})",
        n_queries,
        grind_bits,
        extra_blowup,
        1usize << (1 + extra_blowup)
    );

    /*
     * The tree, if a previous run left it. Loaded before the assembly so the
     * file's cost is paid while nothing else is resident, and so a run that
     * will skip the commitment says so on its first line rather than its
     * hundredth.
     */
    let cache_dir = tree_cache::dir_beside(&out);
    let cached = expected_root.as_deref().and_then(|hex| {
        let path = tree_cache::entry(&cache_dir, hex);
        let t = Instant::now();
        let tree = tree_cache::load(&path);
        match &tree {
            Some(tree) => println!(
                "tree      loaded {} leaves from {} in {:?}",
                tree.len(),
                path.display(),
                t.elapsed()
            ),
            None => println!(
                "tree      none at {}; the commitment will be built",
                path.display()
            ),
        }
        tree
    });
    let loaded = cached.is_some();

    let t0 = Instant::now();
    let mut asm = if real {
        match point.assemble_wired(Point::emit_wiring()) {
            Ok(asm) => asm,
            Err(why) => {
                eprintln!("{why}");
                std::process::exit(2);
            }
        }
    } else {
        assemble(Tamper::None)
    };
    println!(
        "assembly  width={} log_trace_len={} degree={} transitions={} groups={}",
        asm.wired.trace_width(),
        asm.wired.log_trace_len(),
        asm.wired.constraint_degree(),
        asm.wired.num_transition(),
        asm.n_groups
    );
    println!("assembled in {:?}", t0.elapsed());

    /*
     * The statement's public inputs, absorbed into the transcript before
     * anything else so the proof is a proof about them. They are written
     * beside the proof as plain words, because a verifier that mirrors the
     * absorb needs the exact list and not a description of it.
     */
    println!("publics   {} words absorbed first", asm.publics.len());
    let publics_json = format!(
        "{{\n  \"point\": \"{}\",\n  \"artifact\": \"{out}\",\n  \"n_publics\": {},\n  \
         \"absorb\": \"transcript label, then each word as absorb_fp in order, then the trace root\",\n  \
         \"publics\": [{}],\n  \
         \"words_per_intent\": {},\n  \
         \"pool_words\": \"per intent, SPEC section 6 order: six digests, public_amount, fee, \
         asset_id, clearing_price, recipient; a digest and the recipient pack four limbs as \
         limb0 + limb1 * 2^64 + limb2 * 2^128 + limb3 * 2^192\",\n  \
         \"intents\": [\n    {}\n  ]\n}}\n",
        point.name(),
        asm.publics.len(),
        asm.publics
            .iter()
            .map(|v| v.to_u64().to_string())
            .collect::<Vec<_>>()
            .join(", "),
        stark_proofs::shield::join::publics::WORDS,
        pool_intents(&asm.publics).join(",\n    ")
    );
    let publics_out = format!("{out}.publics.json");

    let t2 = Instant::now();
    /*
     * The same value the structure emit writes into
     * `permutation_challenges`. Read here rather than assumed, so a layout
     * saying "transcript" and a prover taking the one round path cannot both
     * be true at once: if this is ever turned off, the emit stops instead of
     * writing an artifact whose layout describes an argument it was not given.
     */
    assert!(
        Point::emit_rounds(),
        "the one round prover would contradict the layout this emit publishes"
    );
    /*
     * Blinding, one polynomial per trace column, seeded from the operating
     * system. A proof opens n_queries rows and a frame more, and for this
     * circuit those cells are the spend; two proofs of one statement sharing a
     * blind hand back the witness in the difference of their openings.
     */
    let deg = stark_proofs::crypto::stark::air::blinding_degree(
        n_queries,
        Air::window_size(&asm.wired),
        1usize << stark_proofs::crypto::stark::fri::FRI_FOLD_LOG,
    );
    let h = stark_proofs::recursion_assembly::inner::hasher();
    let entropy = {
        use std::io::Read;
        let mut buf = [0u8; 256];
        match std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut buf)) {
            Ok(()) => buf.to_vec(),
            Err(e) => {
                eprintln!("no entropy source: {e}");
                Vec::new()
            }
        }
    };
    let Some(seed) = stark_proofs::crypto::stark::air::seed_from_entropy(&entropy) else {
        eprintln!("could not draw a blinding seed; refusing to emit a proof that hides nothing");
        std::process::exit(1);
    };
    let blind: Vec<Vec<stark_proofs::crypto::stark::field::Fp>> = (0..Air::trace_width(&asm.wired))
        .map(|c| stark_proofs::crypto::stark::air::blinding_poly(&h, &seed, c, deg))
        .collect();

    // Before the AIR moves into the prover: the identity is a fact about the
    // circuit and the point, not about the proof that comes back.
    let params = ParamSet::of(&asm.wired, n_queries, grind_bits, extra_blowup);
    let mut witness = core::mem::take(&mut asm.witness);
    let Some((rounds, tree, proved)) = stark_prove_ext_rounds(
        asm.wired,
        &mut witness,
        n_queries,
        grind_bits,
        extra_blowup,
        &asm.publics,
        cached,
        &blind,
    ) else {
        /*
         * Only a watcher can cancel, and this binary passes none, so reaching
         * here means the prover's own contract changed underneath it. Say so
         * and leave nothing on disk rather than carrying on with a hole.
         */
        eprintln!("no proof: the cached periodic tree is not this circuit's (its root moved), or the prover was stopped");
        std::process::exit(1);
    };
    println!("proved in {:?}", t2.elapsed());
    println!(
        "sidecar   {} periodic claims at z, {} openings",
        rounds.pre.periodic_z.len(),
        rounds.pre.openings.len()
    );
    let (beta, gamma) = proved.challenges();
    println!(
        "rounds    region root {}, permutation root {}, split at column {}",
        hex_of(&rounds.pre.proof.trace_root),
        hex_of(&rounds.perm_root),
        rounds.region_width
    );
    println!(
        "challenge beta {} gamma {} drawn from the region root",
        beta.to_u64(),
        gamma.to_u64()
    );

    /*
     * The witness is read by the prover and by nothing after it. Off the heap
     * before the tree is written, which is the next large thing this process
     * touches.
     */
    drop(core::mem::take(&mut asm.witness));

    let root = tree.root();
    let root_hex = hex_of(&root);
    println!("periodic root {root_hex}");
    if let Some(expected) = &expected_root {
        if *expected != root_hex {
            eprintln!(
                "the tree's root is {root_hex} and root= said {expected}; this outer at this \
                 rate does not have that root, refusing to write a proof against it"
            );
            std::process::exit(1);
        }
    }

    if !loaded {
        let path = tree_cache::entry(&cache_dir, &root_hex);
        let t = Instant::now();
        match tree_cache::store(&path, &tree) {
            Ok(()) => println!(
                "tree      stored at {} in {:?}",
                path.display(),
                t.elapsed()
            ),
            Err(e) => eprintln!("tree      not stored at {}: {e}", path.display()),
        }
    }
    drop(tree);

    /*
     * The composition at z, replayed from the proof's own transcript. It is
     * not a field of the artifact and the chain takes it as a claim, so an
     * emit without it makes its reader solve the DEEP identity for it.
     */
    let mut proved = proved;
    let replayed = replay_comp_z_pre(
        &mut proved,
        &rounds.pre,
        Some(&rounds.perm_root),
        extra_blowup,
        &asm.publics,
    )
    .unwrap_or_else(|why| panic!("the proof does not replay: {why}"));
    println!(
        "comp_z    [{}, {}] at z [{}, {}]",
        replayed.comp_z.c0.to_u64(),
        replayed.comp_z.c1.to_u64(),
        replayed.z.c0.to_u64(),
        replayed.z.c1.to_u64()
    );
    let publics_json = publics_json.replace(
        "\n  \"intents\"",
        &format!(
            "\n  \"z\": [{}, {}],\n  \"comp_z\": [{}, {}],\n  \"intents\"",
            replayed.z.c0.to_u64(),
            replayed.z.c1.to_u64(),
            replayed.comp_z.c0.to_u64(),
            replayed.comp_z.c1.to_u64()
        ),
    );

    let t3 = Instant::now();
    let why = stark_verify_ext_rounds_why(
        proved,
        &rounds,
        n_queries,
        grind_bits,
        extra_blowup,
        &root,
        &asm.publics,
    );
    println!(
        "verified against the baked root and the publics in {:?}: {}",
        t3.elapsed(),
        why.is_ok()
    );
    if let Err(check) = why {
        eprintln!("the proof did not verify against its own root: {check}; nothing written");
        std::process::exit(1);
    }

    let bytes = serialize_rounds(&rounds, &params);
    std::fs::write(&out, &bytes).expect("write proof");
    println!("wrote {} bytes to {out}", bytes.len());
    std::fs::write(&publics_out, &publics_json).expect("write publics");
    println!("wrote {} publics to {publics_out}", asm.publics.len());
}
