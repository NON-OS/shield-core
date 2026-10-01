// NONOS Operating System (AGPL-3.0-or-later)

use crate::crypto::stark::air::{
    stark_prove, stark_verify, Air, MultiMembership, Permutation2, Poseidon,
    Squaring, TraceFold, Wired, RATE,
};
use crate::crypto::stark::field::Fp;
use crate::crypto::stark::fri::root_of_unity;
use crate::crypto::stark::poseidon_merkle::PoseidonMerkleTree;
use alloc::boxed::Box;

extern crate alloc;
use alloc::vec::Vec;
#[allow(unused_imports)]
use super::{exec::*, poseidon::*, membership::*, fri::*, monolith::*, ext::*, recursive::*, wired::*, fri_fold::*, fri_fused::*, ext_deep::*, fold_chain::*, membership_multi::*};

/// One FRI query's fold path, split into the pieces an in-circuit fold witnesses:
/// the per-layer challenge, the opened pairs, the public inverse points and
/// position bits, and the committed final value.
#[allow(clippy::type_complexity)]
pub(super) fn trace_fold_data(
    query: usize,
) -> (Vec<Fp>, Vec<Fp>, Vec<Fp>, Vec<Fp>, Vec<bool>, Fp, u32, usize) {
    trace_fold_data_seeded(query, 0xf01d_1234u64 | 1)
}

/// The same fold path over a codeword seeded by `seed`; a different seed folds a
/// different codeword with a different challenge set.
#[allow(clippy::type_complexity)]
pub(super) fn trace_fold_data_seeded(
    query: usize,
    seed: u64,
) -> (Vec<Fp>, Vec<Fp>, Vec<Fp>, Vec<Fp>, Vec<bool>, Fp, u32, usize) {
    trace_fold_data_seeded_first(query, seed, None)
}

// The same seeded fold, but with an optional first-layer challenge. A recursive
// verifier's FRI fold must run on the challenge its transcript squeezed, so the
// monolith overrides `beta[0]` with that challenge and wires the two together.
#[allow(clippy::type_complexity)]
pub(super) fn trace_fold_data_seeded_first(
    query: usize,
    seed: u64,
    first_beta: Option<Fp>,
) -> (Vec<Fp>, Vec<Fp>, Vec<Fp>, Vec<Fp>, Vec<bool>, Fp, u32, usize) {
    let (k, n_folds, log_layers) = (5u32, 4usize, 3u32);
    let n = 1usize << k;
    let inv2 = Fp::from_u64(2).inv();
    let base_omega = root_of_unity(k);
    let shift = Fp::from_u64(7);

    let mut s = seed | 1;
    let mut layers: Vec<Vec<Fp>> = Vec::new();
    let mut betas: Vec<Fp> = Vec::new();
    let mut cur: Vec<Fp> = (0..n).map(|_| Fp::from_u64(xs(&mut s))).collect();
    layers.push(cur.clone());
    let mut omega = base_omega;
    let mut coset = shift;
    for layer_i in 0..n_folds {
        let beta = match first_beta {
            Some(b0) if layer_i == 0 => b0,
            _ => Fp::from_u64(xs(&mut s)),
        };
        betas.push(beta);
        let half = cur.len() / 2;
        let mut next = Vec::with_capacity(half);
        let mut x = coset;
        for i in 0..half {
            let (a, b) = (cur[i], cur[i + half]);
            next.push((a + b) * inv2 + beta * ((a - b) * inv2 * x.inv()));
            x = x * omega;
        }
        cur = next;
        layers.push(cur.clone());
        omega = omega.square();
        coset = coset.square();
    }

    let (mut a, mut b, mut x_inv, mut dir) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut om = base_omega;
    let mut cs = shift;
    for layer in layers.iter().take(n_folds) {
        let half = layer.len() / 2;
        let i = query % half;
        a.push(layer[i]);
        b.push(layer[i + half]);
        x_inv.push((cs * om.pow(i as u64)).inv());
        dir.push(i >= half / 2);
        om = om.square();
        cs = cs.square();
    }
    a.push(layers[n_folds][0]);
    b.push(layers[n_folds][1]);
    let final_value = layers[n_folds][0];
    (betas, a, b, x_inv, dir, final_value, log_layers, n_folds)
}

#[test]
fn an_in_circuit_fold_verifies() {
    // The fold with its folding challenge witnessed in column zero, proven the
    // same as the public-challenge fold. This is the shape the monolith wires.
    let (beta, a, b, x_inv, dir, final_value, log_layers, n_folds) = trace_fold_data(6);
    let air = TraceFold::new(log_layers, n_folds, x_inv, dir, final_value);
    let trace = air.trace(&beta, &a, &b);
    let proof = stark_prove(&air, &trace, QUERIES);
    assert!(stark_verify(&air, &proof, QUERIES), "an honest in-circuit fold was rejected");
}

#[test]
fn a_corrupted_in_circuit_fold_is_rejected() {
    let (beta, mut a, b, x_inv, dir, final_value, log_layers, n_folds) = trace_fold_data(6);
    a[0] = a[0] + Fp::ONE; // an opened value that no longer folds
    let air = TraceFold::new(log_layers, n_folds, x_inv, dir, final_value);
    let trace = air.trace(&beta, &a, &b);
    let proof = stark_prove(&air, &trace, QUERIES);
    assert!(!stark_verify(&air, &proof, QUERIES), "a broken in-circuit fold verified");
}

#[test]
fn a_fold_bound_to_its_challenge_source_verifies() {
    // A supplier region produces the first folding challenge; the in-circuit fold
    // consumes it. The wiring forces the fold to run on exactly the supplied
    // challenge: the transcript-to-fold binding on a real fold.
    let (beta, a, b, x_inv, dir, final_value, log_layers, n_folds) = trace_fold_data(6);
    let source = squaring_trace(3, beta[0]); // column zero holds beta[0] at row 0
    let fold = TraceFold::new(log_layers, n_folds, x_inv, dir, final_value);
    let fold_trace = fold.trace(&beta, &a, &b);

    let mut sigma: Vec<usize> = (0..16).collect();
    sigma.swap(0, 8); // source row 0 wired to fold row 0 (fused row 8)

    let regions: Vec<Box<dyn Air>> =
        alloc::vec![Box::new(Squaring { log_t: 3, seed: beta[0] }), Box::new(fold),];
    let wired = Wired::new(regions, alloc::vec![0], sigma, Fp::from_u64(5), Fp::from_u64(7));
    let witness = wired.trace(&[source, fold_trace]);
    let proof = stark_prove(&wired, &witness, QUERIES);
    assert!(stark_verify(&wired, &proof, QUERIES), "a fold bound to its challenge was rejected");
}

#[test]
fn a_fold_using_the_wrong_challenge_is_rejected() {
    // The fold is internally valid and the supplier is internally valid, but the
    // fold's challenge is not the one the supplier produced. The wiring rejects.
    let (beta, a, b, x_inv, dir, final_value, log_layers, n_folds) = trace_fold_data(6);
    let source = squaring_trace(3, beta[0] + Fp::ONE); // supplies a different value
    let fold = TraceFold::new(log_layers, n_folds, x_inv, dir, final_value);
    let fold_trace = fold.trace(&beta, &a, &b);

    let mut sigma: Vec<usize> = (0..16).collect();
    sigma.swap(0, 8);

    let regions: Vec<Box<dyn Air>> =
        alloc::vec![Box::new(Squaring { log_t: 3, seed: beta[0] + Fp::ONE }), Box::new(fold),];
    let wired = Wired::new(regions, alloc::vec![0], sigma, Fp::from_u64(5), Fp::from_u64(7));
    let witness = wired.trace(&[source, fold_trace]);
    let proof = stark_prove(&wired, &witness, QUERIES);
    assert!(!stark_verify(&wired, &proof, QUERIES), "a fold on the wrong challenge verified");
}

#[test]
fn a_fold_bound_to_both_its_challenge_and_opening_verifies() {
    // The monolith's per-query binding: the fold must run on the transcript's
    // challenge AND the opening's revealed value. A width-two source supplies
    // both in one row; the wiring binds column zero (the challenge) and column
    // one (the opened value) at once.
    let (beta, a, b, x_inv, dir, final_value, log_layers, n_folds) = trace_fold_data(6);
    let (rc0, rc1) = (Fp::from_u64(13), Fp::from_u64(17));
    let (source, out) = permutation2_trace(3, beta[0], a[0], rc0, rc1);
    let fold = TraceFold::new(log_layers, n_folds, x_inv, dir, final_value);
    let fold_trace = fold.trace(&beta, &a, &b);

    let mut sigma: Vec<usize> = (0..32).collect();
    sigma.swap(0, 16); // source row 0 col 0 (challenge) <-> fold row 0 col 0
    sigma.swap(1, 17); // source row 0 col 1 (opening)   <-> fold row 0 col 1

    let regions: Vec<Box<dyn Air>> =
        alloc::vec![Box::new(Permutation2 { log_t: 3, rc0, rc1, out }), Box::new(fold)];
    let wired = Wired::new(regions, alloc::vec![0, 1], sigma, Fp::from_u64(5), Fp::from_u64(7));
    let witness = wired.trace(&[source, fold_trace]);
    let proof = stark_prove(&wired, &witness, QUERIES);
    assert!(
        stark_verify(&wired, &proof, QUERIES),
        "a fold bound to challenge and opening was rejected"
    );
}

#[test]
fn a_fold_bound_to_a_wrong_opening_is_rejected() {
    // The source supplies the right challenge but a different opened value; the
    // multi-column wiring catches the opening even though the challenge matches.
    let (beta, a, b, x_inv, dir, final_value, log_layers, n_folds) = trace_fold_data(6);
    let (rc0, rc1) = (Fp::from_u64(13), Fp::from_u64(17));
    let (source, out) = permutation2_trace(3, beta[0], a[0] + Fp::ONE, rc0, rc1);
    let fold = TraceFold::new(log_layers, n_folds, x_inv, dir, final_value);
    let fold_trace = fold.trace(&beta, &a, &b);

    let mut sigma: Vec<usize> = (0..32).collect();
    sigma.swap(0, 16);
    sigma.swap(1, 17);

    let regions: Vec<Box<dyn Air>> =
        alloc::vec![Box::new(Permutation2 { log_t: 3, rc0, rc1, out }), Box::new(fold)];
    let wired = Wired::new(regions, alloc::vec![0, 1], sigma, Fp::from_u64(5), Fp::from_u64(7));
    let witness = wired.trace(&[source, fold_trace]);
    let proof = stark_prove(&wired, &witness, QUERIES);
    assert!(!stark_verify(&wired, &proof, QUERIES), "a fold on a wrong opening verified");
}

/// A single Merkle opening whose committed leaf is the scalar `v` (a FRI leaf is
/// `[v, 0, 0, 0]`), at an even index so the scalar lands in column zero. Returns
/// the opening trace, the AIR, and its `opened_cells()` map.
pub(super) fn opening_of_scalar(v: Fp, log_rounds: u32) -> (Vec<Fp>, MultiMembership, Vec<(usize, usize)>) {
    let hasher = Poseidon::new(log_rounds, [Fp::ZERO; RATE]);
    let mut leaves = merkle_leaves(4);
    leaves[2] = [v, Fp::ZERO, Fp::ZERO, Fp::ZERO];
    let tree = PoseidonMerkleTree::commit(&hasher, &leaves);
    let opening = opening_at(&tree, &leaves, 2);
    let mem = MultiMembership::new(hasher, log_rounds, alloc::vec![opening]);
    let trace = mem.trace();
    let cells = mem.opened_cells();
    (trace, mem, cells)
}
