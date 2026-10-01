// NONOS Operating System (AGPL-3.0-or-later)

use crate::crypto::stark::air::{
    MerkleMembership, Poseidon, RATE,
};
use crate::crypto::stark::field::Fp;
use crate::crypto::stark::poseidon_merkle::PoseidonMerkleTree;

extern crate alloc;
use alloc::vec::Vec;
#[allow(unused_imports)]
use super::{exec::*, poseidon::*, membership::*, fri::*, fold::*, monolith::*, recursive::*, wired::*, fri_fold::*, fri_fused::*, ext_deep::*, fold_chain::*, membership_multi::*};

// The money-grade composition, compose_ext, evaluates the constraints at the
// out-of-domain point z in Fp2. It must faithfully extend the base compose: on a
// base-embedded point with base-embedded inputs, it returns the embedded base
// result. This ties the Fp2 composition algebra to the already-tested one.
#[test]
fn compose_ext_faithfully_extends_compose() {
    use crate::crypto::stark::air::{compose, compose_ext, Air, Fibonacci};
    use crate::crypto::stark::field::Fp2;
    use crate::crypto::stark::fri::root_of_unity;

    let air = Fibonacci { log_t: 4 };
    let g = root_of_unity(air.log_trace_len());
    let mut s = 0xF1B0u64 | 1;
    let rnd = |s: &mut u64| {
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        Fp::from_u64(*s)
    };

    for _ in 0..200 {
        let x = rnd(&mut s);
        let window: alloc::vec::Vec<Fp> = (0..air.window_size()).map(|_| rnd(&mut s)).collect();
        let periodic: alloc::vec::Vec<Fp> = alloc::vec::Vec::new();
        let ncoeff = air.num_transition() + air.boundary().len();
        let coeffs: alloc::vec::Vec<Fp> = (0..ncoeff).map(|_| rnd(&mut s)).collect();

        let base = compose(&air, g, x, &window, &periodic, &coeffs);

        let window_e: alloc::vec::Vec<Fp2> = window.iter().map(|v| Fp2::from_base(*v)).collect();
        let periodic_e: alloc::vec::Vec<Fp2> =
            periodic.iter().map(|v| Fp2::from_base(*v)).collect();
        let coeffs_e: alloc::vec::Vec<Fp2> = coeffs.iter().map(|v| Fp2::from_base(*v)).collect();
        let ext = compose_ext(&air, g, Fp2::from_base(x), &window_e, &periodic_e, &coeffs_e);

        assert_eq!(Fp2::from_base(base), ext, "compose_ext diverged from compose");
    }
}

// The full money-grade DEEP STARK, end to end on a real computation: the OOD point
// is drawn from Fp2, the composition and DEEP polynomial live in Fp2, and the
// low-degree test is the money-grade FRI with grinding. An honest trace verifies;
// any corrupted row breaks a transition and is rejected.
pub(super) fn fib_trace(t: usize) -> alloc::vec::Vec<Fp> {
    let mut trace = alloc::vec![Fp::ONE, Fp::ONE];
    for i in 2..t {
        let next = trace[i - 1] + trace[i - 2];
        trace.push(next);
    }
    trace
}

#[test]
fn the_money_grade_stark_verifies_a_fibonacci_trace() {
    use crate::crypto::stark::air::{stark_prove_ext, stark_verify_ext, Fibonacci};
    let air = Fibonacci { log_t: 4 };
    let trace = fib_trace(1 << 4);
    let proof = stark_prove_ext(&air, &trace, 32, 8);
    assert!(stark_verify_ext(&air, &proof, 32, 8), "honest money-grade STARK rejected");
}

#[test]
fn a_tampered_money_grade_trace_is_rejected() {
    use crate::crypto::stark::air::{stark_prove_ext, stark_verify_ext, Fibonacci};
    let air = Fibonacci { log_t: 4 };
    let mut trace = fib_trace(1 << 4);
    trace[7] = trace[7] + Fp::ONE; // breaks the recurrence at a non-exempt row
    let proof = stark_prove_ext(&air, &trace, 32, 8);
    assert!(!stark_verify_ext(&air, &proof, 32, 8), "a tampered money-grade trace verified");
}

// The value-conservation constraint, proven money-grade: a running-sum accumulator
// whose signed addends (inputs positive, outputs and fee negative) must cancel. A
// balanced set verifies; any imbalance (value created) breaks the end boundary and
// is rejected. This is the no-inflation gate, proven at ~2^-128 soundness.
pub(super) fn neg(x: u64) -> Fp {
    Fp::ZERO - Fp::from_u64(x)
}

pub(super) fn accumulator_trace(addends: &[Fp]) -> alloc::vec::Vec<Fp> {
    let mut trace = alloc::vec::Vec::with_capacity(addends.len() * 2);
    let mut acc = Fp::ZERO;
    for &a in addends {
        trace.push(acc); // column 0: running total
        trace.push(a); // column 1: addend
        acc = acc + a;
    }
    trace
}

#[test]
fn the_money_grade_stark_proves_value_conservation() {
    use crate::crypto::stark::air::{stark_prove_ext, stark_verify_ext, Accumulator};
    let air = Accumulator { log_t: 3 };
    // inputs 7, 3; outputs 8, 1; fee 1; padding 0, 0. First seven sum to zero.
    let addends =
        [Fp::from_u64(7), Fp::from_u64(3), neg(8), neg(1), neg(1), Fp::ZERO, Fp::ZERO, Fp::ZERO];
    let trace = accumulator_trace(&addends);
    let proof = stark_prove_ext(&air, &trace, 32, 8);
    assert!(stark_verify_ext(&air, &proof, 32, 8), "a balanced (conserving) trace was rejected");
}

#[test]
fn the_money_grade_stark_rejects_inflation() {
    use crate::crypto::stark::air::{stark_prove_ext, stark_verify_ext, Accumulator};
    let air = Accumulator { log_t: 3 };
    // The addends no longer cancel: one extra unit of value is created.
    let addends =
        [Fp::from_u64(7), Fp::from_u64(3), neg(8), neg(1), Fp::ZERO, Fp::ZERO, Fp::ZERO, Fp::ZERO];
    let trace = accumulator_trace(&addends);
    let proof = stark_prove_ext(&air, &trace, 32, 8);
    assert!(!stark_verify_ext(&air, &proof, 32, 8), "an inflating trace verified");
}

// Poseidon proven INSIDE the money-grade STARK: knowledge of a preimage that
// hashes to a public digest, at ~2^-128 soundness. This is the primitive private
// membership and nullifier derivation are built from (a Merkle path is a chain of
// these compressions). Honest preimage verifies; a forged digest is rejected.
#[test]
fn the_money_grade_stark_proves_a_poseidon_preimage() {
    use crate::crypto::stark::air::{stark_prove_ext, stark_verify_ext};
    let params = Poseidon::new(POSEIDON_LOG_T, [Fp::ZERO; RATE]);
    let (trace, digest) = poseidon_trace(&params, absorb(sample_input()), POSEIDON_LOG_T);
    let air = Poseidon::new(POSEIDON_LOG_T, digest);
    let proof = stark_prove_ext(&air, &trace, 32, 8);
    assert!(stark_verify_ext(&air, &proof, 32, 8), "honest money-grade poseidon preimage rejected");
}

#[test]
fn a_money_grade_poseidon_forged_digest_is_rejected() {
    use crate::crypto::stark::air::{stark_prove_ext, stark_verify_ext};
    let params = Poseidon::new(POSEIDON_LOG_T, [Fp::ZERO; RATE]);
    let (trace, digest) = poseidon_trace(&params, absorb(sample_input()), POSEIDON_LOG_T);
    let mut wrong = digest;
    wrong[0] = wrong[0] + Fp::ONE;
    let air = Poseidon::new(POSEIDON_LOG_T, wrong);
    let proof = stark_prove_ext(&air, &trace, 32, 8);
    assert!(
        !stark_verify_ext(&air, &proof, 32, 8),
        "a forged digest verified in the money-grade STARK"
    );
}

// Private set membership proven at money-grade soundness: a leaf opens to a public
// Poseidon-Merkle root without the leaf appearing in the public statement. This is
// the core of the pool's membership check (and nullifier derivation is the same
// hash-chain shape). Honest opening verifies; a wrong root is rejected.
pub(super) fn prove_membership_ext(
    hasher: &Poseidon,
    leaves: &[[Fp; RATE]],
    index: usize,
    log_rounds: u32,
) -> bool {
    use crate::crypto::stark::air::{stark_prove_ext, stark_verify_ext};
    let tree = PoseidonMerkleTree::commit(hasher, leaves);
    let root = tree.root();
    let path = tree.open(index);
    let directions: Vec<bool> = (0..path.len()).map(|k| (index >> k) & 1 == 1).collect();
    let trace = membership_trace(hasher, leaves[index], &path, &directions, log_rounds);
    let air = MerkleMembership::new(hasher.clone(), log_rounds, root, path, directions);
    let proof = stark_prove_ext(&air, &trace, 32, 8);
    stark_verify_ext(&air, &proof, 32, 8)
}

#[test]
fn the_money_grade_stark_proves_merkle_membership() {
    let log_rounds = 3u32;
    let hasher = Poseidon::new(log_rounds, [Fp::ZERO; RATE]);
    assert!(
        prove_membership_ext(&hasher, &merkle_leaves(8), 5, log_rounds),
        "money-grade membership rejected"
    );
}

#[test]
fn a_money_grade_membership_for_a_wrong_root_is_rejected() {
    use crate::crypto::stark::air::{stark_prove_ext, stark_verify_ext};
    let log_rounds = 3u32;
    let hasher = Poseidon::new(log_rounds, [Fp::ZERO; RATE]);
    let leaves = merkle_leaves(8);
    let index = 5usize;
    let tree = PoseidonMerkleTree::commit(&hasher, &leaves);
    let path = tree.open(index);
    let directions: Vec<bool> = (0..path.len()).map(|k| (index >> k) & 1 == 1).collect();
    let trace = membership_trace(&hasher, leaves[index], &path, &directions, log_rounds);
    let mut wrong = tree.root();
    wrong[0] = wrong[0] + Fp::ONE;
    let air = MerkleMembership::new(hasher.clone(), log_rounds, wrong, path, directions);
    let proof = stark_prove_ext(&air, &trace, 32, 8);
    assert!(
        !stark_verify_ext(&air, &proof, 32, 8),
        "a money-grade membership for a wrong root verified"
    );
}

// Range by bit decomposition, proven money-grade: the value peels into booleans and
// the remainder reaches zero, so it fits the bit width. An out-of-range value leaves
// a nonzero remainder and is rejected. This is the overflow guard on note values.
pub(super) fn range_trace(value: u64, log_t: u32) -> alloc::vec::Vec<Fp> {
    let t = 1usize << log_t;
    let mut trace = alloc::vec::Vec::with_capacity(t * 2);
    let mut acc = value;
    for i in 0..t {
        let bit = if i < t - 1 { acc & 1 } else { 0 };
        trace.push(Fp::from_u64(acc));
        trace.push(Fp::from_u64(bit));
        if i < t - 1 {
            acc >>= 1;
        }
    }
    trace
}
