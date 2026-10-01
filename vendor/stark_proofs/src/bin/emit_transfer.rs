// NONOS Operating System (AGPL-3.0-or-later)
//! Emit one private transfer proof at the transfer point and write it out.
//!
//! This is the proof a sender makes: two notes in, two notes out, membership
//! against a pool of the deployed depth. The aggregation proof that settles a
//! whole batch on chain is a different and far larger object; this is the one
//! an ordinary transaction costs.
//!
//! Two things this binary got wrong for as long as it existed, both of which
//! made its output look like the artifact it is named after without being it.
//!
//! It proved at `shield_params::rehearsal::dev`: 32 queries at rate one half with grind 8,
//! which is forty conjectured bits and a development point. The transfer point
//! is 64 queries at rate a quarter with grind 16, the same security settlement
//! reaches by a different trade.
//!
//! And it proved in one round with the keccak transcript, so the copy
//! constraint in it was argued at layout constants. A wallet's proof is a
//! Poseidon proof in two rounds, because the recursion folds it in circuit and
//! because the challenges have to come out of a transcript.
//!
//! Written and then read back through the codec, against an AIR rebuilt from
//! the statement, because a proof is only worth what it is worth to somebody
//! who was not there when it was made.

use stark_proofs::crypto::stark::air::{
    adopt_rounds_challenges, periodic_root_poseidon, stark_prove_poseidon_pre_rounds,
    stark_verify_poseidon_rounds, Air,
};
use stark_proofs::proof_wire::{deserialize_p_rounds, serialize_p_rounds};
use stark_proofs::recursion_assembly::inner::{hasher, LOG_ROUNDS};
use stark_proofs::shield::key::Break;
use stark_proofs::shield::test::scenario::balanced_deployed;
use stark_proofs::shield_params::rehearsal::transfer;
use std::time::Instant;

fn main() {
    let out = std::env::args().nth(1).unwrap_or_else(|| "transfer.proof".into());
    let h = hasher();
    let nq = transfer::N_QUERIES;
    let grind = transfer::GRIND_BITS;
    let extra = transfer::EXTRA_BLOWUP_BITS;

    let t0 = Instant::now();
    let js = balanced_deployed(Break::None);
    println!(
        "instance  trace_width={} log_trace_len={} degree={} periodic={} publics={}",
        js.wired.trace_width(),
        js.wired.log_trace_len(),
        js.wired.constraint_degree(),
        js.wired.periodic_columns().len(),
        js.intent.len()
    );
    println!(
        "point     transfer: {nq} queries, grind {grind}, extra blowup {extra}, \
         poseidon log_rounds {LOG_ROUNDS}"
    );
    println!("built in {:?}", t0.elapsed());

    let publics = js.intent.clone();
    let root = periodic_root_poseidon(&js.wired, extra, &h);
    let mut witness = js.witness;

    let t1 = Instant::now();
    let Some((rounds, air_after)) = stark_prove_poseidon_pre_rounds(
        js.wired, &mut witness, nq, grind, extra, &h, &publics, &[],
    ) else {
        eprintln!("the join-split carries no permutation columns above its regions");
        std::process::exit(1);
    };
    println!("proved in {:?}", t1.elapsed());
    let (beta, gamma) = air_after.wired().challenges_ext();
    println!(
        "rounds    split at column {}, beta ({}, {}) gamma ({}, {})",
        rounds.region_width,
        beta.c0.to_u64(),
        beta.c1.to_u64(),
        gamma.c0.to_u64(),
        gamma.c1.to_u64()
    );
    drop(witness);

    let bytes = serialize_p_rounds(&rounds);
    std::fs::write(&out, &bytes).expect("write proof");
    println!("wrote {} bytes to {out}", bytes.len());

    /*
     * From the bytes, and against an AIR rebuilt from the statement rather than
     * the one the prover left behind. A verifier has neither, and a round trip
     * that reuses either shows the prover agrees with itself.
     */
    let read = deserialize_p_rounds(&bytes).expect("the proof we just wrote did not parse");
    let mut fresh = balanced_deployed(Break::None).wired;
    adopt_rounds_challenges(&mut fresh, &h, &publics, &read.pre.proof.trace_root);
    assert!(
        fresh.wired().challenges_ext() == (beta, gamma),
        "the decoded region root draws other challenges"
    );

    let t2 = Instant::now();
    let ok =
        stark_verify_poseidon_rounds(&mut fresh, &read, nq, grind, extra, &h, &publics, &root);
    println!("verified from disk in {:?}: {ok}", t2.elapsed());

    if !ok {
        eprintln!("the emitted transfer proof did not verify");
        std::process::exit(1);
    }
}
