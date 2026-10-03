// NONOS Operating System (AGPL-3.0-or-later)
//! The transfer pinned proofs (docs/17): the pinned transfer in the three accepted
//! query shapes, and a withdrawal whose fee is within the pool's cap, each
//! proved on the format 7 transcript, verified from its format 7 bytes, and given a
//! rank certificate. Written to `spec/transfer/` with a manifest.
//!
//! The `not_before` build writes its own set to `spec/not-before/`: the same
//! requests with word 36 set to `NB_T`, and the withdrawal at the pool's flat
//! fee rather than the old 0.5% cap, which the pool's amount policy refuses.
//! The `claim` build writes `spec/claim/`: the same requests, words 36 and 37
//! the inputs' limb sums, which the prover computes and no request carries.
//!
//!     cargo test --release -p nox_prover --features fri8,parallel -- \
//!         transfer_emit --ignored --nocapture
#![cfg(feature = "fri8")]

use stark_proofs::crypto::stark::air::{
    domain_params_blown, share_paths, stark_prove_ext_rounds, stark_verify_ext_rounds_positions,
    stark_verify_ext_rounds_shared_why,
};
use stark_proofs::crypto::stark::field::Fp;
use stark_proofs::crypto::stark::fri::FRI_FOLD_LOG;
use stark_proofs::crypto::stark::fri_ext::QUERY_SHAPES;
use stark_proofs::crypto::stark::hash::keccak256;
use stark_proofs::host::{build_parts_with, Entropy};
use stark_proofs::proof_wire::{
    deserialize_rounds_shared, serialize_rounds, serialize_rounds_shared, ParamSet,
};
use stark_proofs::recursion_assembly::inner::{hasher, hide_at};
use stark_proofs::shield::batch::assemble;
use stark_proofs::shield::join::{join_split_shape, JoinSplit};
use stark_proofs::shield::member::TREE_DEPTH;
use stark_proofs::shield_params::direct;
use stark_proofs::zk_rank::check_fri_rank_shape;

const SPEC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../spec");

/// Where this build's pinned set goes.
const OUT: &str = if cfg!(feature = "not_before") {
    "not-before"
} else if cfg!(feature = "claim") {
    "claim"
} else {
    "transfer"
};

/// The builds whose withdrawal pays the flat fee and whose set carries the
/// live-sized withdrawal.
const FLAT: bool = cfg!(any(feature = "not_before", feature = "claim"));

/// The earliest settlement time the `not_before` set proves at: on the grid.
const NB_T: u64 = 1_790_000_400;

/// The ETH flat fee of the pool's amount policy, `rules(0).fee`, in wei.
const FLAT_FEE: u64 = 50_000_000_000_000;

/// A request as this build proves it: word 36 set in the `not_before` build.
fn this_build(request: String) -> String {
    if cfg!(feature = "not_before") {
        request.replacen('{', &format!("{{\"not_before\": {NB_T}, "), 1)
    } else {
        request
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn read(dir: &str, name: &str) -> String {
    std::fs::read_to_string(format!("{dir}/{name}")).expect("a pinned vector file")
}

/// The withdrawal vector's request with its fee at 0.5% of the public amount,
/// the pool's cap, and the change output raised by the difference.
fn withdraw_capped_request() -> String {
    let r = read(
        &format!("{SPEC}/wallet-vectors/withdraw-eth"),
        "request.json",
    );
    if FLAT {
        return withdraw_flat_request(r);
    }
    let r = r.replace("\"fee\": 100000000000000,", "\"fee\": 10000000000000,");
    r.replace(
        "\"output_values\": [1900000000000000, 0],",
        "\"output_values\": [1990000000000000, 0],",
    )
}

/// The withdrawal at the flat fee, the change output raised by the difference
/// from the vector's fee.
fn withdraw_flat_request(r: String) -> String {
    let change = 1_900_000_000_000_000 + (100_000_000_000_000 - FLAT_FEE);
    let r = r.replace(
        "\"fee\": 100000000000000,",
        &format!("\"fee\": {FLAT_FEE},"),
    );
    r.replace(
        "\"output_values\": [1900000000000000, 0],",
        &format!("\"output_values\": [{change}, 0],"),
    )
}

/// A fixture pool of two 1e16 notes under one fixture secret, spent as a
/// 1e16 withdrawal at the flat fee with the change back to the spender. The
/// secrets are `fixture::secret(101)`: test value, they spend nothing.
fn withdraw_live() -> (String, String) {
    use stark_proofs::crypto::stark::air::{Poseidon, RATE};
    use stark_proofs::host::pack_u256;
    use stark_proofs::shield::member::PoolTree;
    use stark_proofs::shield::note::{note_parts, POOL_LOG_ROUNDS};
    use stark_proofs::shield::test::fixture::{owned, secret};

    const NOTE: u64 = 10_000_000_000_000_000;
    let h = Poseidon::new(POOL_LOG_ROUNDS, [Fp::ZERO; RATE]);
    let sk = secret(101);
    let notes = [owned(sk, 11, NOTE), owned(sk, 12, NOTE)];
    let cms: Vec<String> = notes.iter().map(|n| pack_u256(&note_parts(n).cm)).collect();
    let mut tree = PoolTree::with_depth(h, TREE_DEPTH);
    for n in &notes {
        tree.insert(note_parts(n).cm);
    }
    let root = pack_u256(&tree.root());
    let change = NOTE - FLAT_FEE;
    let request = format!(
        "{{\n  \"asset_id\": 0,\n  \"pool_leaves\": [\"{a}\", \"{b}\"],\n  \"assoc_leaves\": [\"{a}\", \"{b}\"],\n  \
         \"input_pool_index\": [0, 1],\n  \"input_assoc_index\": [0, 1],\n  \"note_root\": \"{root}\",\n  \
         \"assoc_root\": \"{root}\",\n  \"recipient\": \"0x8ba1f109551bd432803012645ac136ddd64dba72\",\n  \
         \"fee_recipient\": \"0x5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b\",\n  \"clearing_price\": 1000000,\n  \
         \"public_amount\": {NOTE},\n  \"fee\": {FLAT_FEE},\n  \"output_values\": [{change}, 0],\n  \
         \"output_spend_pk\": [\"self\", \"self\"]\n}}\n",
        a = cms[0],
        b = cms[1],
    );
    let limbs = sk
        .iter()
        .map(|v| v.to_u64().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let note = |n: &stark_proofs::shield::note::Note| {
        format!(
            "{{\"value\": {}, \"asset_id\": {}, \"spend_pk\": {:?}, \"blinding\": {:?}}}",
            n.value, n.asset_id, n.spend_pk, n.blinding
        )
    };
    let seed = format!(
        "{{\n  \"artifact\": \"live-seed\",\n  \"warning\": \"fixture secrets for a test vector; they spend nothing\",\n  \
         \"secrets\": [[{limbs}], [{limbs}]],\n  \"notes\": [{}, {}]\n}}\n",
        note(&notes[0]),
        note(&notes[1])
    );
    (request, seed)
}

struct Emitted {
    name: String,
    shape: u8,
    q: usize,
    grind: u32,
    bytes: usize,
    sha: String,
    params: String,
    periodic_root: String,
    deep_nonce: u64,
    rank: String,
    secs: f64,
}

fn prove_one(
    name: &str,
    request: &str,
    seed: &str,
    entropy: &[u8],
    shape: (u8, usize, u32),
) -> Emitted {
    let (id, q, grind) = shape;
    let extra = direct::EXTRA_BLOWUP_BITS;
    let start = std::time::Instant::now();
    let stream = crate::hedge::hedge(entropy, seed, request).expect("entropy");
    let mut e = Entropy::new(&stream);
    let (parts, _) = {
        let mut w = |n: usize| e.words(n);
        build_parts_with(request, seed, &mut w).expect("the request builds")
    };
    let mut b = assemble(vec![parts.parts]);
    let intent = b.intents.pop().expect("one statement");
    let mut js = JoinSplit {
        wired: b.wired,
        witness: b.witness,
        intent,
    };
    let h = hasher();
    let w = e.words(4).expect("entropy");
    let blind = hide_at(
        &h,
        &mut js,
        &[w[0], w[1], w[2], w[3]],
        q,
        1usize << FRI_FOLD_LOG,
    );
    let params = ParamSet::of(&js.wired, q, grind, extra);
    let publics = js.intent.clone();
    let mut witness = js.witness;
    let (rounds, tree, _air) = stark_prove_ext_rounds(
        js.wired,
        &mut witness,
        q,
        grind,
        extra,
        &publics,
        None,
        &blind,
    )
    .expect("proves");
    let root = tree.root();
    let secs = start.elapsed().as_secs_f64();

    // Verify in memory, share the paths, write format 7, then verify the bytes.
    let verifier = join_split_shape(TREE_DEPTH, &publics);
    let log_n = domain_params_blown(&verifier, extra).0;
    let positions =
        stark_verify_ext_rounds_positions(verifier, &rounds, q, grind, extra, &root, &publics)
            .expect("the transfer proof verifies");
    let shared = share_paths(&rounds, &positions, log_n).expect("paths share");
    let f7 = serialize_rounds_shared(&rounds, &shared, &params);
    let (skeleton, streams) =
        deserialize_rounds_shared(&f7, &params).expect("format 7 parses back");
    let v = join_split_shape(TREE_DEPTH, &publics);
    stark_verify_ext_rounds_shared_why(v, &skeleton, &streams, q, grind, extra, &root, &publics)
        .expect("the format 7 bytes verify");

    // A shape other than the proof's is refused.
    let (_, oq, og) = QUERY_SHAPES[(QUERY_SHAPES.iter().position(|s| s.0 == id).unwrap() + 1) % 3];
    let v = join_split_shape(TREE_DEPTH, &publics);
    assert!(
        stark_verify_ext_rounds_shared_why(v, &skeleton, &streams, oq, og, extra, &root, &publics)
            .is_err(),
        "another shape's parameters accepted the proof"
    );

    let words: Vec<u64> = publics.iter().map(|v| v.to_u64()).collect();
    let f5 = serialize_rounds(&rounds, &params);
    let r = check_fri_rank_shape(&f5, &words, 3, q, grind).expect("rank check runs");
    assert!(
        r.holds,
        "{name} shape {id}: rank {} of {}",
        r.mask_rank, r.bound
    );

    let dir = format!("{SPEC}/{OUT}/{name}-shape{id}");
    std::fs::create_dir_all(&dir).expect("the pinned set's directory");
    std::fs::write(format!("{dir}/proof.bin"), &f7).expect("write");
    std::fs::write(format!("{dir}/request.json"), request).expect("write");
    let pubs: Vec<String> = words.iter().map(|w| w.to_string()).collect();
    std::fs::write(
        format!("{dir}/publics.json"),
        format!("{{\"publics\": [{}]}}\n", pubs.join(", ")),
    )
    .expect("write");
    let _ = Fp::ZERO;
    Emitted {
        name: name.into(),
        shape: id,
        q,
        grind,
        bytes: f7.len(),
        sha: hex(&keccak256(&f7)),
        params: hex(&params.id()),
        periodic_root: hex(&root),
        deep_nonce: rounds.pre.deep_nonce,
        rank: format!("{} of {}", r.mask_rank, r.bound),
        secs,
    }
}

#[test]
#[ignore = "release tier: proves the transfer pinned proofs"]
fn transfer_emit() {
    let tdir = format!("{SPEC}/wallet-vectors/transfer-eth");
    let wdir = format!("{SPEC}/wallet-vectors/withdraw-eth");
    let ent = |dir: &str| -> Vec<u8> {
        let h = read(dir, "entropy.hex");
        let h = h.trim();
        (0..h.len() / 2)
            .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).expect("hex"))
            .collect()
    };
    let mut out = Vec::new();
    for s in QUERY_SHAPES {
        let e = prove_one(
            "transfer-eth",
            &this_build(read(&tdir, "request.json")),
            &read(&tdir, "seed.json"),
            &ent(&tdir),
            s,
        );
        println!(
            "{} shape {} q {} grind {}: {} bytes, {:.1} s",
            e.name, e.shape, e.q, e.grind, e.bytes, e.secs
        );
        out.push(e);
    }
    let wname = if FLAT {
        "withdraw-flat"
    } else {
        "withdraw-capped"
    };
    let e = prove_one(
        wname,
        &this_build(withdraw_capped_request()),
        &read(&wdir, "seed.json"),
        &ent(&wdir),
        QUERY_SHAPES[0],
    );
    println!(
        "{} shape {}: {} bytes, {:.1} s",
        e.name, e.shape, e.bytes, e.secs
    );
    out.push(e);

    // A withdrawal the live pool's amount policy accepts: 1e16 wei, the
    // smallest standard ETH amount, at the flat fee.
    if FLAT {
        let (request, seed) = withdraw_live();
        let e = prove_one(
            "withdraw-live",
            &this_build(request),
            &seed,
            &ent(&wdir),
            QUERY_SHAPES[0],
        );
        println!(
            "{} shape {}: {} bytes, {:.1} s",
            e.name, e.shape, e.bytes, e.secs
        );
        out.push(e);
    }

    let title = if cfg!(feature = "claim") {
        format!("# claim pinned proofs\n\nThe 38-word statement: words 36 and 37 the two input notes' limb sums, the total `lo + hi * 2^32`. Withdrawals at the flat fee {FLAT_FEE} wei. ")
    } else if cfg!(feature = "not_before") {
        format!("# not_before pinned proofs\n\nThe 37-word statement, word 36 `not_before` = {NB_T} on the 600-second grid, withdrawal at the flat fee {FLAT_FEE} wei. ")
    } else {
        String::from("# Transfer pinned proofs\n\n")
    };
    let mut m = title + &String::from("The format 7 transcript (docs/17), format 7, 32-byte digests, radix 8, periodic overlay, the checkpoint rule. Each proof was verified from its format 7 bytes, refused under another shape's parameters, and given a rank certificate.\n\n| proof | shape | queries | grind | bytes | keccak256 | parameter id | DEEP nonce | rank | prove s |\n|---|---|---|---|---|---|---|---|---|---|\n");
    for e in &out {
        m.push_str(&format!(
            "| {}-shape{} | {} | {} | {} | {} | `{}` | `{}` | {} | {} | {:.1} |\n",
            e.name,
            e.shape,
            e.shape,
            e.q,
            e.grind,
            e.bytes,
            e.sha,
            e.params,
            e.deep_nonce,
            e.rank,
            e.secs
        ));
    }
    m.push_str(&format!("\nPeriodic root: `{}`\n", out[0].periodic_root));
    assert!(
        out.iter().all(|e| e.periodic_root == out[0].periodic_root),
        "one circuit, one periodic root"
    );
    std::fs::write(format!("{SPEC}/{OUT}/MANIFEST.md"), m).expect("manifest");
}
