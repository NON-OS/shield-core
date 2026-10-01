// NONOS Operating System (AGPL-3.0-or-later)
//! One FRI query's verifier fused into a single proof, and the four tampers
//! that must break it.

use crate::crypto::stark::air::{
    stark_prove, stark_verify, Air, Fused,
    Squaring, Wired,
};
use crate::crypto::stark::field::Fp;
use alloc::boxed::Box;

extern crate alloc;
use alloc::vec::Vec;
#[allow(unused_imports)]
use super::{fri::*, exec::*, poseidon::*, membership::*, fold::*, monolith::*, ext::*, recursive::*, wired::*, fri_fold::*, ext_deep::*, fold_chain::*, membership_multi::*};

#[test]
fn a_fri_query_verifier_is_fused_into_one_proof() {
    // The two halves of a FRI query check, a Merkle opening under the committed
    // root and the fold consistency down the layers, are different-width AIRs.
    // Fused, they are proven and verified as a single STARK: the verification
    // cost of the whole query verifier stays that of one proof.
    let (mem_trace, mem) = merkle_region(3, 3);
    let (fold_trace, fold) = fri_fold_region(6);

    let regions: Vec<Box<dyn Air>> = alloc::vec![Box::new(mem), Box::new(fold)];
    let fused = Fused::new(regions);
    let witness = fused.trace(&[mem_trace, fold_trace]);
    let proof = stark_prove(&fused, &witness, QUERIES);
    assert!(stark_verify(&fused, &proof, QUERIES), "the fused query verifier was rejected");
}

#[test]
fn a_tampered_region_breaks_the_fused_proof() {
    // Corrupt one opened value in the fold region of the fused trace. The single
    // proof must fail: a fault in any region breaks the whole verification.
    let (mem_trace, mem) = merkle_region(3, 3);
    let (fold_trace, fold) = fri_fold_region(6);

    let mem_rows = 1usize << mem.log_trace_len();
    let regions: Vec<Box<dyn Air>> = alloc::vec![Box::new(mem), Box::new(fold)];
    let fused = Fused::new(regions);
    let mut witness = fused.trace(&[mem_trace, fold_trace]);
    // The fold region starts after the membership region; corrupt its first cell.
    let width = 8usize;
    witness[mem_rows * width] = witness[mem_rows * width] + Fp::ONE;
    let proof = stark_prove(&fused, &witness, QUERIES);
    assert!(!stark_verify(&fused, &proof, QUERIES), "a tampered fused region verified");
}

#[test]
fn a_tampered_ood_frame_is_rejected() {
    // The out-of-domain frame is the point where the constraints are actually
    // checked. A frame that lies about the trace breaks the DEEP quotients, and
    // the low-degree test rejects.
    let seed = Fp::from_u64(3);
    let air = Squaring { log_t: 3, seed };
    let mut proof = stark_prove(&air, &squaring_trace(3, seed), QUERIES);
    proof.ood_frame[0] = proof.ood_frame[0] + Fp::ONE;
    assert!(!stark_verify(&air, &proof, QUERIES), "a tampered ood frame verified");
}

#[test]
fn a_value_is_bound_across_two_fused_regions() {
    // Region A computes a value; region B starts from it. A copy constraint over
    // column zero forces A's last cell to equal B's first, so the two regions,
    // each internally valid, must agree on the shared value. This is how a
    // transcript's squeezed challenge binds to where a fold consumes it.
    let a_trace = squaring_trace(3, Fp::from_u64(3));
    let handoff = a_trace[7];
    let b_trace = squaring_trace(3, handoff);

    let mut sigma: Vec<usize> = (0..16).collect();
    sigma.swap(7, 8); // A's last cell (row 7) wired to B's first (row 8)

    let regions: Vec<Box<dyn Air>> = alloc::vec![
        Box::new(Squaring { log_t: 3, seed: Fp::from_u64(3) }),
        Box::new(Squaring { log_t: 3, seed: handoff }),
    ];
    let wired = Wired::new(regions, alloc::vec![0], sigma, Fp::from_u64(5), Fp::from_u64(7));
    let witness = wired.trace(&[a_trace, b_trace]);
    let proof = stark_prove(&wired, &witness, QUERIES);
    assert!(stark_verify(&wired, &proof, QUERIES), "an honest cross-region binding was rejected");
}

#[test]
fn a_broken_cross_region_binding_is_rejected() {
    // Region B starts from a different value than A produced. Each region is
    // internally valid, but the wiring forces the shared cell equal, so the
    // single proof must fail.
    let a_trace = squaring_trace(3, Fp::from_u64(3));
    let handoff = a_trace[7];
    let wrong = handoff + Fp::ONE;
    let b_trace = squaring_trace(3, wrong);

    let mut sigma: Vec<usize> = (0..16).collect();
    sigma.swap(7, 8);

    let regions: Vec<Box<dyn Air>> = alloc::vec![
        Box::new(Squaring { log_t: 3, seed: Fp::from_u64(3) }),
        Box::new(Squaring { log_t: 3, seed: wrong }),
    ];
    let wired = Wired::new(regions, alloc::vec![0], sigma, Fp::from_u64(5), Fp::from_u64(7));
    let witness = wired.trace(&[a_trace, b_trace]);
    let proof = stark_prove(&wired, &witness, QUERIES);
    assert!(!stark_verify(&wired, &proof, QUERIES), "a broken cross-region binding verified");
}
