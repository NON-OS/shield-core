// NONOS Operating System (AGPL-3.0-or-later)
//! Prove a transfer from a witness a wallet wrote.
//!
//! The wallet builds a spend and writes it as witness words; this reads them, rebuilds the transfer,
//! proves it at the transfer point in two Poseidon rounds, and verifies the
//! proof back from its own bytes against a circuit rebuilt from the statement.
//!
//! Nothing here knows the fixture. Every private value comes out of the file and
//! every public one is computed from it, so a proof this produces is a proof
//! about the wallet's spend rather than about a spend the prover invented.
//!
//!     prove_from_witness <witness.wit> [transfer.proof]
//!
//! The witness is a flat little-endian `u64` file. It is read whole and its
//! length checked against the depth in its header before a word is used, so a
//! truncated or foreign file is refused rather than half-read.

use stark_proofs::crypto::stark::air::{
    periodic_root_poseidon, rounds_challenges, stark_prove_poseidon_pre_rounds,
    stark_verify_poseidon_rounds, Air, Permuted,
};
use stark_proofs::proof_wire::{deserialize_p_rounds, serialize_p_rounds};
use stark_proofs::recursion_assembly::inner::hasher;
use stark_proofs::shield::witness_wire;
use stark_proofs::shield_params::rehearsal::transfer;
use std::time::Instant;

fn die(why: &str) -> ! {
    eprintln!("{why}");
    std::process::exit(1)
}

/// The file as words. Refused unless it is a whole number of them, because a
/// trailing byte means the writer and this disagree about the unit.
fn words(path: &str) -> Vec<u64> {
    let bytes = std::fs::read(path).unwrap_or_else(|e| die(&format!("cannot read {path}: {e}")));
    if !bytes.len().is_multiple_of(8) {
        die(&format!(
            "{path} is {} bytes, which is not a whole number of words",
            bytes.len()
        ));
    }
    bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| u64::from_le_bytes(*c))
        .collect()
}

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(input) = args.next() else {
        die("usage: prove_from_witness <witness.wit> [transfer.proof]")
    };
    let out = args.next().unwrap_or_else(|| "transfer.proof".into());

    let w = witness_wire::read(&words(&input)).unwrap_or_else(|why| die(&format!("{input}: {why}")));
    println!(
        "witness   depth {}, in {} and {}, out {} and {}, public {} fee {}",
        w.depth,
        w.inputs[0].value,
        w.inputs[1].value,
        w.outputs[0].value,
        w.outputs[1].value,
        w.public_amount,
        w.fee
    );

    let t0 = Instant::now();
    let js = w.join_split();
    println!(
        "circuit   trace_width={} log_trace_len={} degree={} publics={} built in {:?}",
        js.wired.trace_width(),
        js.wired.log_trace_len(),
        js.wired.constraint_degree(),
        js.intent.len(),
        t0.elapsed()
    );

    /*
     * The statement is the circuit's, not the file's. The witness carried the
     * two roots because the pool published them, and everything else in the
     * intent, the nullifiers and the created commitments, is derived here. A
     * wallet that disagrees with these words has written a spend it cannot
     * settle, and it finds out now rather than on chain.
     */
    let h = hasher();
    let publics = js.intent.clone();
    let root = periodic_root_poseidon(&js.wired, transfer::EXTRA_BLOWUP_BITS, &h);
    let mut witness = js.witness;

    let t1 = Instant::now();
    let Some((rounds, _air)) = stark_prove_poseidon_pre_rounds(
        js.wired,
        &mut witness,
        transfer::N_QUERIES,
        transfer::GRIND_BITS,
        transfer::EXTRA_BLOWUP_BITS,
        &h,
        &publics,
        &[],
    ) else {
        die("the join-split carries no permutation columns above its regions")
    };
    println!(
        "proved    {} queries, grind {}, extra blowup {}, in {:?}",
        transfer::N_QUERIES,
        transfer::GRIND_BITS,
        transfer::EXTRA_BLOWUP_BITS,
        t1.elapsed()
    );
    drop(witness);

    let bytes = serialize_p_rounds(&rounds);
    std::fs::write(&out, &bytes).unwrap_or_else(|e| die(&format!("cannot write {out}: {e}")));
    println!("wrote     {} bytes to {out}", bytes.len());

    /*
     * Back from the bytes, against a circuit rebuilt from the same witness. A
     * verifier holds neither the prover's memory nor the challenges it left in
     * force, so anything that survives only in one of those is not part of the
     * proof.
     */
    let read = deserialize_p_rounds(&bytes).unwrap_or_else(|| die("the proof just written does not parse"));
    let mut fresh = w.join_split().wired;
    let (beta, gamma) = rounds_challenges(&h, &publics, &read.pre.proof.trace_root);
    fresh.set_challenges(beta, gamma);

    let t2 = Instant::now();
    let ok = stark_verify_poseidon_rounds(
        &mut fresh,
        &read,
        transfer::N_QUERIES,
        transfer::GRIND_BITS,
        transfer::EXTRA_BLOWUP_BITS,
        &h,
        &publics,
        &root,
    );
    println!("verified  from disk in {:?}: {ok}", t2.elapsed());
    if !ok {
        die("the proof does not verify against the statement its own witness determines")
    }

    /*
     * The settled words, so whoever relays this can check the intent against
     * what the wallet expected before it pays for calldata.
     */
    let limbs: Vec<String> = publics.iter().map(|v| v.to_u64().to_string()).collect();
    println!("intent    [{}]", limbs.join(","));
}
