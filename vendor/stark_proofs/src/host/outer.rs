// NONOS Operating System (AGPL-3.0-or-later)

//! The settlement outer proved, verified and written, once, for every tool
//! that makes one.
//!
//! Two programs make the outer the chain verifies: the one process prover
//! that proves a wallet's spend end to end, and the relayer that folds an
//! inner proof it was handed. Everything after the assembly is the same in
//! both and is written here so the two cannot drift: the blinding, the cached
//! periodic tree, the proof at the deployment point, the replay of z and the
//! composition at z, the verification against the baked root before a byte
//! is written, and the two files.

use super::request::{die, pack_u256};
use crate::crypto::stark::air::replay_pre::replay_comp_z_pre;
use crate::crypto::stark::air::{
    blinding_degree, blinding_poly, seed_from_entropy, stark_prove_ext_rounds,
    stark_verify_ext_rounds_why, Air, Poseidon, RATE,
};
use crate::crypto::stark::field::{Fp, Fp2};
use crate::crypto::stark::fri::FRI_FOLD_LOG;
use crate::crypto::stark::merkle::DIGEST_BYTES;
use crate::proof_wire::{serialize_rounds, ParamSet};
use crate::recursion_assembly::Assembly;
use crate::shield_params::{provable_bits, security_bits, settlement};
use crate::tree_cache;
use std::io::Read;
use std::time::Instant;

pub struct Settled {
    pub bytes: usize,
    pub root_hex: String,
    pub z: Fp2,
    pub comp_z: Fp2,
}

/// A soundness point by name: queries, grind bits, extra blowup bits.
pub type Point = (usize, u32, u32);

/// The point a tool proves the outer at: the settlement point, point B. Any
/// other `point=` is refused, because a proof at the wrong point is a proof the
/// verifier walks and rejects after the settler has paid for it.
pub fn point_from_args(args: &[String]) -> Point {
    match args.iter().find_map(|a| a.strip_prefix("point=")) {
        None | Some("settlement") => (
            settlement::N_QUERIES,
            settlement::GRIND_BITS,
            settlement::EXTRA_BLOWUP_BITS,
        ),
        Some(other) => die(&format!(
            "point={other}: not a point; the one point is settlement"
        )),
    }
}

/// Prove the assembled outer at `point`, verify it against its own periodic
/// root and the publics it absorbed, and write `out` and `out.publics.json`.
/// Nothing is written if it does not verify.
///
/// `expected_root` names a cached periodic tree beside `out`; without it the
/// tree is built and cached under the root it turns out to have.
pub fn prove_outer(
    rh: &Poseidon,
    asm: Assembly,
    out: &str,
    expected_root: Option<&str>,
    point: Point,
) -> Settled {
    prove_outer_as(rh, asm, out, expected_root, point, Verdict::Refuse)
}

/// What a proof that fails its own verification does to the run.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing is written. Every tool that makes a proof for the chain.
    Refuse,
    /// Written anyway and marked `"forged": true`, for the forgery a verifier
    /// must be shown to refuse. Only `forge_statement` asks for this.
    Record,
}

/// `prove_outer`, with the verdict on a proof that does not verify chosen.
pub fn prove_outer_as(
    rh: &Poseidon,
    mut asm: Assembly,
    out: &str,
    expected_root: Option<&str>,
    point: Point,
    verdict: Verdict,
) -> Settled {
    println!(
        "assembly  width={} log_trace_len={} degree={} transitions={}",
        asm.wired.trace_width(),
        asm.wired.log_trace_len(),
        asm.wired.constraint_degree(),
        asm.wired.num_transition()
    );
    println!("publics   {} words absorbed first", asm.publics.len());

    let (n_queries, grind_bits, extra_blowup) = point;
    println!(
        "point     {n_queries} queries, {grind_bits} grind bits, extra blowup {extra_blowup}, {} conjectured and {} provable bits",
        security_bits(n_queries, grind_bits, extra_blowup),
        provable_bits(n_queries, grind_bits, extra_blowup)
    );
    let cache_dir = tree_cache::dir_beside(out);
    let cached =
        expected_root.and_then(|hex| tree_cache::load(&tree_cache::entry(&cache_dir, hex)));
    let loaded = cached.is_some();
    println!(
        "tree      {}",
        if loaded {
            "loaded from cache"
        } else {
            "will be built"
        }
    );

    // The outer lands on chain, so its openings are public. A layer-zero leaf
    // holds 2^FRI_FOLD_LOG points, and the degree covers each of them and its
    // successors: `air::blinding_degree`.
    let deg = blinding_degree(
        n_queries,
        Air::window_size(&asm.wired),
        1usize << FRI_FOLD_LOG,
    );
    let entropy = {
        let mut buf = [0u8; 256];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut buf))
            .unwrap_or_else(|e| die(&format!("no entropy source: {e}")));
        buf.to_vec()
    };
    let Some(bseed) = seed_from_entropy(&entropy) else {
        die("could not draw a blinding seed; refusing to emit a proof that hides nothing")
    };
    let blind: Vec<Vec<Fp>> = (0..Air::trace_width(&asm.wired))
        .map(|c| blinding_poly(rh, &bseed, c, deg))
        .collect();

    let publics = asm.publics.clone();
    // Before the AIR moves into the prover: the identity is a fact about the
    // circuit and the point, not about the proof that comes back.
    let params = ParamSet::of(&asm.wired, n_queries, grind_bits, extra_blowup);
    let mut witness = core::mem::take(&mut asm.witness);
    let t3 = Instant::now();
    let Some((rounds, tree, proved)) = stark_prove_ext_rounds(
        asm.wired,
        &mut witness,
        n_queries,
        grind_bits,
        extra_blowup,
        &publics,
        cached,
        &blind,
    ) else {
        die("no proof: the cached periodic tree is not this circuit's (its root moved), or the prover was stopped")
    };
    drop(witness);
    println!("proved in {:?}", t3.elapsed());

    let root = tree.root();
    let root_hex: String = root[..DIGEST_BYTES]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    println!("periodic root {root_hex}");
    if !loaded {
        let _ = tree_cache::store(&tree_cache::entry(&cache_dir, &root_hex), &tree);
    }
    drop(tree);

    /*
     * The composition at z, which the verifier on chain takes as a claim
     * beside the proof rather than recomputing. It is not in the artifact:
     * it is what the outer's constraints evaluate to on the frame, and the
     * outer's constants include the inner transcript this run bound, so only
     * this process can state it. Replayed from the proof's own transcript
     * under the publics the prover absorbed, so the point is the one the
     * proof opened.
     */
    let mut proved = proved;
    let replayed = replay_comp_z_pre(
        &mut proved,
        &rounds.pre,
        Some(&rounds.perm_root),
        extra_blowup,
        &publics,
    )
    .unwrap_or_else(|why| panic!("the outer's own proof does not replay: {why}"));
    println!(
        "comp_z    [{}, {}] at z [{}, {}]",
        replayed.comp_z.c0.to_u64(),
        replayed.comp_z.c1.to_u64(),
        replayed.z.c0.to_u64(),
        replayed.z.c1.to_u64()
    );

    /*
     * The public pins take the words the verifier is handed, not the words
     * the circuit was assembled over: that is the check a proof of one
     * statement under another statement's transcript has to fail.
     */
    let bound = proved.bind_public_pins(&publics);
    if !bound && verdict == Verdict::Refuse {
        die("the publics do not match the circuit's public pins; nothing written");
    }
    let t4 = Instant::now();
    let why = if bound {
        stark_verify_ext_rounds_why(
            proved,
            &rounds,
            n_queries,
            grind_bits,
            extra_blowup,
            &root,
            &publics,
        )
    } else {
        Err("the publics do not match the circuit's public pins")
    };
    println!(
        "verified against the baked root and the publics in {:?}: {}",
        t4.elapsed(),
        why.is_ok()
    );
    let forged = match (why, verdict) {
        (Ok(()), _) => false,
        (Err(check), Verdict::Refuse) => die(&format!(
            "the proof did not verify against its own root: {check}; nothing written"
        )),
        (Err(check), Verdict::Record) => {
            println!(
                "FORGED    refused here ({check}); written for the verifier under test to refuse"
            );
            true
        }
    };

    let bytes = serialize_rounds(&rounds, &params);
    std::fs::write(out, &bytes).unwrap_or_else(|e| die(&format!("cannot write {out}: {e}")));
    println!("wrote {} bytes to {out}", bytes.len());

    let quad = |at: usize| -> [Fp; RATE] { core::array::from_fn(|i| publics[at + i]) };
    let words: Vec<String> = publics.iter().map(|v| v.to_u64().to_string()).collect();
    let publics_out = format!("{out}.publics.json");
    std::fs::write(
        &publics_out,
        format!(
            "{{\n  \"artifact\": \"{out}\",\n  \"note_root\": \"{}\",\n  \"assoc_root\": \"{}\",\n  \
             \"forged\": {forged},\n  \"n_publics\": {},\n  \"publics\": [{}],\n  \"z\": [{}, {}],\n  \"comp_z\": [{}, {}]\n}}\n",
            pack_u256(&quad(0)),
            pack_u256(&quad(RATE)),
            publics.len(),
            words.join(", "),
            replayed.z.c0.to_u64(),
            replayed.z.c1.to_u64(),
            replayed.comp_z.c0.to_u64(),
            replayed.comp_z.c1.to_u64()
        ),
    )
    .unwrap_or_else(|e| die(&format!("cannot write {publics_out}: {e}")));
    println!("wrote {} publics to {publics_out}", publics.len());

    Settled {
        bytes: bytes.len(),
        root_hex,
        z: replayed.z,
        comp_z: replayed.comp_z,
    }
}
