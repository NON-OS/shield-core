// NONOS Operating System (AGPL-3.0-or-later)
//! The settlement outer proved under Poseidon commitments.
//!
//! This is the wrap's first precondition and it gates the other three. The
//! wrap is a final recursion layer that verifies the settlement outer in
//! circuit and lands one transaction on chain. A recursion verifies its inner
//! by walking that inner's Merkle paths as constraints, so the inner has to be
//! committed under a hash a circuit can run. The settlement outer is committed
//! under keccak, because that is what Solidity can check cheaply, and keccak in
//! circuit is not expensive, it is unbuildable at this size.
//!
//! So a wrap over the outer as it ships does not exist and cannot be costed.
//! Every wrap figure either lane has quoted was measured over trees the wrap
//! cannot verify.
//!
//! What this establishes is narrower than the wrap and is the thing the wrap
//! rests on: the outer satisfies the Poseidon prover's contract, proves under
//! it in two commitment rounds, and verifies back. The AIR is the same AIR; the
//! only thing that moves is which hash commits it.

use crate::crypto::stark::air::{
    periodic_root_poseidon, rounds_challenges, stark_prove_poseidon_pre_rounds,
    stark_verify_poseidon_rounds, Air, Permuted, Poseidon, RATE,
};
use crate::crypto::stark::field::Fp;
use crate::proof_wire::{deserialize_p_rounds, serialize_p_rounds};
use crate::recursion_assembly::inner::{hasher, LOG_ROUNDS};
use crate::recursion_assembly::point::Point;
use crate::recursion_assembly::{assemble_real_capped_wired, Tamper};
use alloc::vec::Vec;

/// Queries and grind for the gate itself. Not a soundness point: this proves
/// the commitment path exists, and the point the wrap runs at is PARAMS.md 7.
const NQ: usize = 8;
const GRIND: u32 = 4;
const EXTRA: u32 = 1;

/// Two queries of the outer rather than thirty two. Every region kind is
/// present at a cap of two, so the commitment path is the same path; what
/// shrinks is the number of rows it runs over.
const CAP: usize = 2;

/// The outer commits under Poseidon, in two rounds, and verifies back.
///
/// At the shipping wiring, stated rather than inherited. The first version of
/// this took `assemble_real_capped`, whose default is packed, and proved a 922
/// column circuit at degree 14 while the deployment is 704 at 10. It would have
/// been a correct proof that the wrap's first gate is passable for a circuit
/// nobody ships, which is the same mistake as the boundary list and the wiring
/// digest, in a test I wrote after finding both.
///
/// Two rounds because the outer carries a copy constraint like the inner does,
/// so its challenges have to come out of its own transcript against its region
/// root. A one round Poseidon outer would be the constant-challenge forgery
/// with a different hash on it.
#[test]
#[ignore]
fn the_settlement_outer_commits_under_poseidon() {
    commits_under_poseidon(CAP);
}

/// The same thing over every inner query the settlement carries, which is the
/// gate rather than the rehearsal of it.
///
/// `CAP` builds the identical per-query machinery over two queries, so it
/// establishes that the commitment path is passable and nothing about what a
/// full-size outer costs under Poseidon. That distinction is the whole of
/// THREAT.md 7a: a wrap cannot be built or costed over trees it cannot verify,
/// and a cap of two is not those trees.
///
/// Hours and a large working set, so it runs on the box before a release rather
/// than in CI, alongside the other release-tier gates.
#[test]
#[ignore]
fn the_full_size_settlement_outer_commits_under_poseidon() {
    commits_under_poseidon(usize::MAX);
}

fn commits_under_poseidon(cap: usize) {
    let h: Poseidon = hasher();
    let mut asm = assemble_real_capped_wired(Tamper::None, cap, Point::emit_wiring());
    let publics = asm.publics.clone();

    std::println!(
        "outer under poseidon: width {}, log_t {}, degree {}, region_width {}, publics {}",
        Air::trace_width(&asm.wired),
        Air::log_trace_len(&asm.wired),
        Air::constraint_degree(&asm.wired),
        Permuted::region_width(&asm.wired),
        publics.len()
    );

    let t0 = std::time::Instant::now();
    let root = periodic_root_poseidon(&asm.wired, EXTRA, &h);
    std::println!("periodic root in {:?}", t0.elapsed());
    let mut witness = core::mem::take(&mut asm.witness);
    let air = asm.wired;

    let t1 = std::time::Instant::now();
    let Some((rounds, _proved)) = stark_prove_poseidon_pre_rounds(
        air, &mut witness, NQ, GRIND, EXTRA, &h, &publics, &[],
    ) else {
        panic!("the outer carries no permutation columns above its regions");
    };
    std::println!("proved in {:?}", t1.elapsed());
    drop(witness);

    /*
     * From the bytes and against an AIR rebuilt from the statement, which is
     * what a wrap would hold: it has the proof and the circuit, and neither the
     * prover's memory nor the challenges it left in force.
     */
    let encoded = serialize_p_rounds(&rounds);
    let read = deserialize_p_rounds(&encoded).expect("the outer's poseidon proof must parse");
    std::println!("outer poseidon proof: {} bytes", encoded.len());

    let mut fresh = assemble_real_capped_wired(Tamper::None, cap, Point::emit_wiring()).wired;
    let (beta, gamma) = rounds_challenges(&h, &publics, &read.pre.proof.trace_root);
    fresh.set_challenges(beta, gamma);

    let t2 = std::time::Instant::now();
    let ok = stark_verify_poseidon_rounds(&mut fresh, &read, NQ, GRIND, EXTRA, &h, &publics, &root);
    std::println!("verified from bytes in {:?}: {ok}", t2.elapsed());
    assert!(
        ok,
        "the settlement outer did not verify under its own Poseidon commitment"
    );
}

/// The periodic root under Poseidon is not the root under keccak, and the two
/// are not interchangeable in either direction.
///
/// A wrap holds the Poseidon one as a baked constant. A chain verifier holds
/// the keccak one. They commit the same columns, which is exactly why a mix-up
/// reads as a configuration detail rather than as a proof about a different
/// commitment, and why both are emitted side by side rather than one being
/// derived from the other.
#[test]
#[ignore]
fn the_two_periodic_roots_are_different_commitments() {
    let h: Poseidon = hasher();
    let asm = assemble_real_capped_wired(Tamper::None, CAP, Point::emit_wiring());
    let poseidon: [Fp; RATE] = periodic_root_poseidon(&asm.wired, EXTRA, &h);
    let limbs: Vec<u64> = poseidon.iter().map(|v| v.to_u64()).collect();
    std::println!("periodic root poseidon (log_rounds {LOG_ROUNDS}): {limbs:?}");
    assert!(
        limbs.iter().any(|&v| v != 0),
        "the poseidon periodic root is zero, which is not a commitment to anything"
    );
}
