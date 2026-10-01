// NONOS Operating System (AGPL-3.0-or-later)

use crate::crypto::stark::air::{
    stark_prove, stark_verify, CopyConstraint, FiatShamir,     MerkleMembership, MultiMembership, Permutation, Poseidon, RATE, WIDTH,
};
use crate::crypto::stark::field::Fp;
use crate::crypto::stark::fri::root_of_unity;
use crate::crypto::stark::poseidon_merkle::PoseidonMerkleTree;

extern crate alloc;
use alloc::vec::Vec;
#[allow(unused_imports)]
use super::{exec::*, poseidon::*, membership::*, fold::*, monolith::*, ext::*, recursive::*, wired::*, fri_fold::*, fri_fused::*, ext_deep::*, fold_chain::*, membership_multi::*};

pub(super) fn value_leaves(values: &[Fp]) -> Vec<[Fp; RATE]> {
    values
        .iter()
        .map(|v| {
            let mut d = [Fp::ZERO; RATE];
            d[0] = *v;
            d
        })
        .collect()
}

#[test]
fn a_full_fri_query_verifies() {
    // A whole FRI query: fold a codeword, and for each layer prove its two
    // openings are committed with the batched-opening STARK, then check the fold
    // is consistent. The expensive Merkle work is proven; the cheap fold is a
    // public field check. This is FRI query verification, composed from step 2.
    let log_rounds = 3u32;
    let hasher = Poseidon::new(log_rounds, [Fp::ZERO; RATE]);
    let (k, n_folds) = (5u32, 4usize); // domain 32, fold to size 2
    let n = 1usize << k;
    let inv2 = Fp::from_u64(2).inv();
    let base_omega = root_of_unity(k);
    let shift = Fp::from_u64(7);

    // Fold a codeword, keeping every layer and its Poseidon commitment.
    let mut s = 0xf17_u64 | 1;
    let mut layers: Vec<Vec<Fp>> = alloc::vec![(0..n).map(|_| Fp::from_u64(xs(&mut s))).collect()];
    let mut betas: Vec<Fp> = Vec::new();
    let (mut omega, mut coset) = (base_omega, shift);
    for _ in 0..n_folds {
        let beta = Fp::from_u64(xs(&mut s));
        betas.push(beta);
        let cur = layers.last().unwrap().clone();
        let half = cur.len() / 2;
        let mut next = Vec::with_capacity(half);
        let mut x = coset;
        for i in 0..half {
            let (a, b) = (cur[i], cur[i + half]);
            next.push((a + b) * inv2 + beta * ((a - b) * inv2 * x.inv()));
            x = x * omega;
        }
        layers.push(next);
        omega = omega.square();
        coset = coset.square();
    }

    let q = 6usize;
    let (mut om, mut cs) = (base_omega, shift);
    for m in 0..n_folds {
        let size = layers[m].len();
        let half = size / 2;
        let i = q % half;
        let (a, b) = (layers[m][i], layers[m][i + half]);

        // Prove both openings are committed under the layer's root.
        let leaves = value_leaves(&layers[m]);
        let tree = PoseidonMerkleTree::commit(&hasher, &leaves);
        let openings =
            alloc::vec![opening_at(&tree, &leaves, i), opening_at(&tree, &leaves, i + half)];
        let air = MultiMembership::new(hasher.clone(), log_rounds, openings);
        let trace = air.trace();
        let proof = stark_prove(&air, &trace, QUERIES);
        assert!(stark_verify(&air, &proof, QUERIES), "layer {m} openings not proven committed");

        // Check the fold publicly: it must land on the next layer's value.
        let x = cs * om.pow(i as u64);
        let folded = (a + b) * inv2 + betas[m] * ((a - b) * inv2 * x.inv());
        assert_eq!(folded, layers[m + 1][i], "fold at layer {m} inconsistent");
        om = om.square();
        cs = cs.square();
    }
}

/// Build the grand-product column: start at one, multiply by (a+g)/(b+g) per
/// step over the sequence, then carry the final value through the inert tail.
pub(super) fn permutation_trace(a: &[Fp], b: &[Fp], gamma: Fp) -> Vec<Fp> {
    let n = a.len();
    let total = 2 * n;
    let mut z = alloc::vec![Fp::ZERO; total];
    z[0] = Fp::ONE;
    for i in 0..n {
        z[i + 1] = z[i] * (a[i] + gamma) * (b[i] + gamma).inv();
    }
    for i in n..total - 1 {
        z[i + 1] = z[i];
    }
    z
}

#[test]
fn a_copy_constraint_verifies() {
    // sigma has one non-trivial cycle {0, 3}: the wiring requires the values at
    // positions 0 and 3 to be equal. This is how a beta computed in one region
    // is bound to where a fold consumes it in another.
    let sigma = alloc::vec![3usize, 1, 2, 0, 4, 5, 6, 7];
    let values: Vec<Fp> = [5u64, 1, 2, 5, 8, 9, 10, 11].iter().map(|v| Fp::from_u64(*v)).collect();
    let (beta, gamma) = (Fp::from_u64(0x5171), Fp::from_u64(0x9e37));
    let air = CopyConstraint::new(values, sigma, beta, gamma);
    let trace = air.trace();
    let proof = stark_prove(&air, &trace, QUERIES);
    assert!(stark_verify(&air, &proof, QUERIES), "an honest copy constraint was rejected");
}

#[test]
fn a_violated_copy_constraint_is_rejected() {
    // The wiring says positions 0 and 3 are equal, but they are not.
    let sigma = alloc::vec![3usize, 1, 2, 0, 4, 5, 6, 7];
    let values: Vec<Fp> = [5u64, 1, 2, 9, 8, 9, 10, 11].iter().map(|v| Fp::from_u64(*v)).collect();
    let (beta, gamma) = (Fp::from_u64(0x5171), Fp::from_u64(0x9e37));
    let air = CopyConstraint::new(values, sigma, beta, gamma);
    let trace = air.trace();
    let proof = stark_prove(&air, &trace, QUERIES);
    assert!(!stark_verify(&air, &proof, QUERIES), "a violated copy constraint verified");
}

#[test]
fn a_permutation_argument_verifies() {
    // Two sequences with the same multiset: the grand product returns to one.
    let a: Vec<Fp> = (1..=8).map(Fp::from_u64).collect();
    let b: Vec<Fp> = [3u64, 1, 4, 8, 2, 7, 5, 6].iter().map(|v| Fp::from_u64(*v)).collect();
    let gamma = Fp::from_u64(0x9e37_79b9);
    let trace = permutation_trace(&a, &b, gamma);
    let air = Permutation::new(a, b, gamma);
    let proof = stark_prove(&air, &trace, QUERIES);
    assert!(stark_verify(&air, &proof, QUERIES), "an honest permutation was rejected");
}

#[test]
fn a_non_permutation_is_rejected() {
    // Different multisets: the product does not return to one, so the checkpoint
    // fails and the proof is rejected.
    let a: Vec<Fp> = (1..=8).map(Fp::from_u64).collect();
    let b: Vec<Fp> = (2..=9).map(Fp::from_u64).collect();
    let gamma = Fp::from_u64(0x9e37_79b9);
    let trace = permutation_trace(&a, &b, gamma);
    let air = Permutation::new(a, b, gamma);
    let proof = stark_prove(&air, &trace, QUERIES);
    assert!(!stark_verify(&air, &proof, QUERIES), "a non-permutation verified");
}

#[test]
fn a_membership_proof_for_a_wrong_root_is_rejected() {
    let log_rounds = 3u32;
    let hasher = Poseidon::new(log_rounds, [Fp::ZERO; RATE]);
    let leaves = merkle_leaves(8);
    let tree = PoseidonMerkleTree::commit(&hasher, &leaves);
    let index = 5usize;
    let path = tree.open(index);
    let directions: Vec<bool> = (0..path.len()).map(|k| (index >> k) & 1 == 1).collect();
    let trace = membership_trace(&hasher, leaves[index], &path, &directions, log_rounds);

    let mut wrong = tree.root();
    wrong[0] = wrong[0] + Fp::ONE;
    let air = MerkleMembership::new(hasher.clone(), log_rounds, wrong, path, directions);
    let proof = stark_prove(&air, &trace, QUERIES);
    assert!(!stark_verify(&air, &proof, QUERIES), "a wrong-root membership proof verified");
}

/// Run the Poseidon sponge transcript: seed with the first value, then permute
/// and absorb each remaining value, and squeeze the first lane. Returns the
/// trace and the challenge.
pub(super) fn fiat_shamir_trace(
    hasher: &Poseidon,
    inputs: &[Fp],
    log_rounds: u32,
    log_slots: u32,
) -> (Vec<Fp>, Fp) {
    let l = 1usize << log_rounds;
    let blocks = (1usize << log_slots) - 1;
    let mut rows: Vec<[Fp; WIDTH]> = Vec::with_capacity((blocks + 1) * l);
    let mut state = [Fp::ZERO; WIDTH];
    state[0] = inputs[0];
    for k in 0..blocks {
        for round in 0..l {
            rows.push(state);
            state = hasher.round_with_rc(&state, &hasher.round_constant(round));
        }
        if k + 1 < blocks {
            state[0] = state[0] + inputs[k + 1];
        }
    }
    let challenge = state[0];
    for round in 0..l {
        rows.push(state);
        state = hasher.round_with_rc(&state, &hasher.round_constant(round));
    }
    let mut trace = Vec::with_capacity(rows.len() * WIDTH);
    for row in &rows {
        trace.extend_from_slice(row);
    }
    (trace, challenge)
}

#[test]
fn a_fiat_shamir_transcript_verifies() {
    // Prove a challenge was squeezed from a sequence of absorbed values through a
    // Poseidon transcript: challenge derivation, arithmetized, the last piece a
    // recursive verifier needs to run its own Fiat-Shamir in circuit.
    let (log_rounds, log_slots) = (3u32, 2u32); // 8-round permute, 3 absorbs
    let hasher = Poseidon::new(log_rounds, [Fp::ZERO; RATE]);
    let inputs = alloc::vec![Fp::from_u64(111), Fp::from_u64(222), Fp::from_u64(333)];
    let (trace, challenge) = fiat_shamir_trace(&hasher, &inputs, log_rounds, log_slots);

    let air = FiatShamir::new(
        Poseidon::new(log_rounds, [Fp::ZERO; RATE]),
        log_rounds,
        log_slots,
        inputs.clone(),
        challenge,
    );
    let proof = stark_prove(&air, &trace, QUERIES);
    assert!(stark_verify(&air, &proof, QUERIES), "an honest transcript was rejected");

    let bad = FiatShamir::new(
        Poseidon::new(log_rounds, [Fp::ZERO; RATE]),
        log_rounds,
        log_slots,
        inputs,
        challenge + Fp::ONE,
    );
    let bad_proof = stark_prove(&bad, &trace, QUERIES);
    assert!(!stark_verify(&bad, &bad_proof, QUERIES), "a wrong challenge verified");
}
