// NONOS Operating System (AGPL-3.0-or-later)
//! The fold chain: a real codeword folded four times, one query's path down
//! the layers proven consistent in circuit, and the regions it is built from.

use crate::crypto::stark::air::{
    stark_prove, stark_verify, FriFold,     MerkleMembership, Poseidon, RATE,
};
use crate::crypto::stark::field::Fp;
use crate::crypto::stark::fri::root_of_unity;
use crate::crypto::stark::poseidon_merkle::PoseidonMerkleTree;

extern crate alloc;
use alloc::vec::Vec;
#[allow(unused_imports)]
use super::{fri::*, exec::*, poseidon::*, membership::*, fold::*, monolith::*, ext::*, recursive::*, wired::*, fri_fused::*, ext_deep::*, fold_chain::*, membership_multi::*};

#[test]
fn a_fri_fold_chain_verifies() {
    // Fold a real codeword four times, extract one query's path down the layers,
    // and prove inside a STARK that the folds are consistent and reach the
    // committed final value. This is the FRI verifier's fold check, arithmetized.
    let (k, n_folds, log_layers) = (5u32, 4usize, 3u32); // domain 32, fold to size 2
    let n = 1usize << k;
    let inv2 = Fp::from_u64(2).inv();
    let base_omega = root_of_unity(k);
    let shift = Fp::from_u64(7);

    let mut s = 0xf01d_1234u64 | 1;
    let mut layers: Vec<Vec<Fp>> = Vec::new();
    let mut betas: Vec<Fp> = Vec::new();
    let mut cur: Vec<Fp> = (0..n).map(|_| Fp::from_u64(xs(&mut s))).collect();
    layers.push(cur.clone());
    let mut omega = base_omega;
    let mut coset = shift;
    for _ in 0..n_folds {
        let beta = Fp::from_u64(xs(&mut s));
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

    // Extract query q's path (q even so the last fold lands in the first slot).
    let q = 6usize;
    let rows = 1usize << log_layers;
    let mut trace = alloc::vec![Fp::ZERO; rows * 2];
    let (mut x_inv, mut beta_col, mut dir) = (Vec::new(), Vec::new(), Vec::new());
    let mut om = base_omega;
    let mut cs = shift;
    for m in 0..n_folds {
        let half = layers[m].len() / 2;
        let i = q % half;
        trace[m * 2] = layers[m][i];
        trace[m * 2 + 1] = layers[m][i + half];
        x_inv.push((cs * om.pow(i as u64)).inv());
        beta_col.push(betas[m]);
        dir.push(i >= half / 2);
        om = om.square();
        cs = cs.square();
    }
    // Final layer row: its pair, first slot is the committed value.
    trace[n_folds * 2] = layers[n_folds][0];
    trace[n_folds * 2 + 1] = layers[n_folds][1];
    let final_value = layers[n_folds][0];

    let air = FriFold::new(
        log_layers,
        n_folds,
        x_inv.clone(),
        beta_col.clone(),
        dir.clone(),
        final_value,
    );
    let proof = stark_prove(&air, &trace, QUERIES);
    assert!(stark_verify(&air, &proof, QUERIES), "an honest fri fold chain was rejected");

    // Tamper one opened value: the fold no longer lands on the next layer.
    let mut bad = trace.clone();
    bad[2] = bad[2] + Fp::ONE;
    let bad_air = FriFold::new(log_layers, n_folds, x_inv, beta_col, dir, final_value);
    let bad_proof = stark_prove(&bad_air, &bad, QUERIES);
    assert!(!stark_verify(&bad_air, &bad_proof, QUERIES), "a broken fold chain verified");
}

/// One FRI query's fold path: fold a real codeword four times, extract the query
/// column down the layers, and return the fold trace with its AIR. The shape the
/// fold half of a query verifier proves.
pub(super) fn fri_fold_region(query: usize) -> (Vec<Fp>, FriFold) {
    let (k, n_folds, log_layers) = (5u32, 4usize, 3u32);
    let n = 1usize << k;
    let inv2 = Fp::from_u64(2).inv();
    let base_omega = root_of_unity(k);
    let shift = Fp::from_u64(7);

    let mut s = 0xf01d_1234u64 | 1;
    let mut layers: Vec<Vec<Fp>> = Vec::new();
    let mut betas: Vec<Fp> = Vec::new();
    let mut cur: Vec<Fp> = (0..n).map(|_| Fp::from_u64(xs(&mut s))).collect();
    layers.push(cur.clone());
    let mut omega = base_omega;
    let mut coset = shift;
    for _ in 0..n_folds {
        let beta = Fp::from_u64(xs(&mut s));
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

    let rows = 1usize << log_layers;
    let mut trace = alloc::vec![Fp::ZERO; rows * 2];
    let (mut x_inv, mut beta_col, mut dir) = (Vec::new(), Vec::new(), Vec::new());
    let mut om = base_omega;
    let mut cs = shift;
    for m in 0..n_folds {
        let half = layers[m].len() / 2;
        let i = query % half;
        trace[m * 2] = layers[m][i];
        trace[m * 2 + 1] = layers[m][i + half];
        x_inv.push((cs * om.pow(i as u64)).inv());
        beta_col.push(betas[m]);
        dir.push(i >= half / 2);
        om = om.square();
        cs = cs.square();
    }
    trace[n_folds * 2] = layers[n_folds][0];
    trace[n_folds * 2 + 1] = layers[n_folds][1];
    let final_value = layers[n_folds][0];

    (trace, FriFold::new(log_layers, n_folds, x_inv, beta_col, dir, final_value))
}

/// Build the Merkle-opening region for `index` in an eight-leaf tree.
pub(super) fn merkle_region(index: usize, log_rounds: u32) -> (Vec<Fp>, MerkleMembership) {
    // The hasher runs 2^log_rounds rounds, so its compression matches the AIR's
    // per-slot round count and the committed root equals the trace's final digest.
    let hasher = Poseidon::new(log_rounds, [Fp::ZERO; RATE]);
    let leaves = merkle_leaves(8);
    let tree = PoseidonMerkleTree::commit(&hasher, &leaves);
    let root = tree.root();
    let path = tree.open(index);
    let directions: Vec<bool> = (0..path.len()).map(|k| (index >> k) & 1 == 1).collect();
    let trace = membership_trace(&hasher, leaves[index], &path, &directions, log_rounds);
    let air = MerkleMembership::new(hasher, log_rounds, root, path, directions);
    (trace, air)
}
