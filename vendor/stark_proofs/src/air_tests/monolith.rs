// NONOS Operating System (AGPL-3.0-or-later)

use crate::crypto::stark::air::{
    stark_prove, stark_verify, Air, MultiMembership, Poseidon, TraceFold, Wired, RATE,
};
use crate::crypto::stark::field::Fp;
use crate::crypto::stark::poseidon_merkle::PoseidonMerkleTree;
use alloc::boxed::Box;

extern crate alloc;
use alloc::vec::Vec;
#[allow(unused_imports)]
use super::{exec::*, poseidon::*, membership::*, fri::*, fold::*, ext::*, recursive::*, wired::*, fri_fold::*, fri_fused::*, ext_deep::*, fold_chain::*, membership_multi::*};

/// The whole-proof monolith: for each query, a Merkle opening of its codeword
/// value and its in-circuit fold, all fused into one trace. Per query the
/// opening is wired to the fold's opened value; across queries every fold's
/// challenge is wired into one cycle. So one STARK attests, for every query at
/// once, that the fold folded the committed value and that all queries used one
/// challenge set. `seeds[q]` seeds query q; `wrong_opening` makes query 0 commit
/// a value it did not fold.
pub(super) fn whole_proof_monolith(queries: &[usize], seeds: &[u64], wrong_opening: bool) -> (Wired, Vec<Fp>) {
    let mut regions: Vec<Box<dyn Air>> = Vec::new();
    let mut traces: Vec<Vec<Fp>> = Vec::new();
    let mut heights: Vec<usize> = Vec::new();
    let mut open_idx: Vec<usize> = Vec::new();
    let mut fold_idx: Vec<usize> = Vec::new();
    let mut n_folds = 0usize;

    for (qi, (&query, &seed)) in queries.iter().zip(seeds).enumerate() {
        let (beta, a, b, x_inv, dir, fv, ll, nf) = trace_fold_data_seeded(query, seed);
        n_folds = nf;
        let scalar = if wrong_opening && qi == 0 { a[0] + Fp::ONE } else { a[0] };
        let (mtr, mem, _) = opening_of_scalar(scalar, 2);
        open_idx.push(regions.len());
        // The rows the region occupies, not the length of its padded trace.
        heights.push(mem.rows());
        traces.push(mtr);
        regions.push(Box::new(mem));

        let fold = TraceFold::new(ll, nf, x_inv, dir, fv);
        fold_idx.push(regions.len());
        heights.push(1usize << ll);
        traces.push(fold.trace(&beta, &a, &b));
        regions.push(Box::new(fold));
    }

    let mut offsets: Vec<usize> = Vec::new();
    let mut acc = 0usize;
    for &h in &heights {
        offsets.push(acc);
        acc += h;
    }
    let span = acc.next_power_of_two();
    let k = 2usize;
    let mut sigma: Vec<usize> = (0..span * k).collect();

    // Per query: the opening's leaf (column zero) <-> the fold's opened value
    // (column one).
    for qi in 0..queries.len() {
        let leaf = offsets[open_idx[qi]] * k; // (row, col 0)
        let opened = offsets[fold_idx[qi]] * k + 1; // (row, col 1)
        sigma.swap(leaf, opened);
    }
    // Across queries: cycle each layer's folding challenge (column zero).
    let qn = queries.len();
    for m in 0..n_folds {
        for qi in 0..qn {
            let here = (offsets[fold_idx[qi]] + m) * k;
            let next = (offsets[fold_idx[(qi + 1) % qn]] + m) * k;
            sigma[here] = next;
        }
    }

    let wired = Wired::new(regions, alloc::vec![0, 1], sigma, Fp::from_u64(5), Fp::from_u64(7));
    let witness = wired.trace(&traces);
    (wired, witness)
}

#[test]
fn the_whole_fri_verification_is_one_stark() {
    // Two queries, each with its opening and its fold, all in one proof: every
    // fold folded the committed value and both queries used one challenge set.
    let seed = 0xf01d_1234u64 | 1;
    let (wired, witness) = whole_proof_monolith(&[6, 10], &[seed, seed], false);
    let proof = stark_prove(&wired, &witness, QUERIES);
    assert!(stark_verify(&wired, &proof, QUERIES), "the whole-proof monolith was rejected");
}

#[test]
fn the_monolith_rejects_an_uncommitted_fold() {
    // One query folds a value its opening did not commit.
    let seed = 0xf01d_1234u64 | 1;
    let (wired, witness) = whole_proof_monolith(&[6, 10], &[seed, seed], true);
    let proof = stark_prove(&wired, &witness, QUERIES);
    assert!(!stark_verify(&wired, &proof, QUERIES), "the monolith accepted an uncommitted fold");
}

#[test]
fn the_monolith_rejects_a_split_challenge_set() {
    // The two queries fold on different challenge sets.
    let seed = 0xf01d_1234u64 | 1;
    let (wired, witness) = whole_proof_monolith(&[6, 10], &[seed, 0xdead_beef], false);
    let proof = stark_prove(&wired, &witness, QUERIES);
    assert!(!stark_verify(&wired, &proof, QUERIES), "the monolith accepted a split challenge set");
}

#[test]
fn the_fan_out_wiring_is_robust_under_fuzzing() {
    // The wiring invariant across the input space, not just hand-picked cases:
    // over many random query sets, an honest fan-out (all queries on one
    // challenge set) always verifies, and giving one query a different set is
    // always rejected.
    let mut s = 0x9e37_79b9u64 | 1;
    for _ in 0..24 {
        let q_count = 2 + (xs(&mut s) % 3) as usize; // 2..=4 queries
        let queries: Vec<usize> = (0..q_count).map(|_| (xs(&mut s) % 32) as usize).collect();
        let base = xs(&mut s);

        // Honest: every query shares one challenge set.
        let honest = alloc::vec![base; q_count];
        let (w, wit) = multi_query_fanout(&queries, &honest);
        let p = stark_prove(&w, &wit, QUERIES);
        assert!(stark_verify(&w, &p, QUERIES), "honest fan-out rejected: {queries:?}");

        // Dishonest: one query folds on a different set.
        let victim = (xs(&mut s) % q_count as u64) as usize;
        let mut seeds = honest.clone();
        seeds[victim] = base ^ 0xffff_ffff;
        let (w2, wit2) = multi_query_fanout(&queries, &seeds);
        let p2 = stark_prove(&w2, &wit2, QUERIES);
        assert!(!stark_verify(&w2, &p2, QUERIES), "split set accepted: {queries:?} v{victim}");
    }
}

#[test]
fn both_fold_inputs_are_bound_to_committed_openings() {
    // A FRI query opens both f(x) and f(-x). This binds both of the fold's
    // layer-zero inputs to committed Merkle openings, over three wired columns:
    // the fold folds two values, and both are proven committed, not just the
    // first.
    let (beta, a, b, x_inv, dir, final_value, log_layers, n_folds) = trace_fold_data(6);
    let (open_a, mem_a, _) = opening_of_scalar(a[0], 2);
    let (open_b, mem_b, _) = opening_of_scalar(b[0], 2);
    let fold = TraceFold::new(log_layers, n_folds, x_inv, dir, final_value);
    let fold_trace = fold.trace(&beta, &a, &b);

    let mem_h = mem_a.rows();
    let fold_off = 2 * mem_h;
    let k = 3usize;
    let span = (2 * mem_h + (1usize << log_layers)).next_power_of_two();
    let mut sigma: Vec<usize> = (0..span * k).collect();
    // open_a.leaf (row 0, col 0) <-> fold.a (fold_off, col 1)
    sigma.swap(0, fold_off * k + 1);
    // open_b.leaf (row mem_h, col 0) <-> fold.b (fold_off, col 2)
    sigma.swap(mem_h * k, fold_off * k + 2);

    let regions: Vec<Box<dyn Air>> = alloc::vec![Box::new(mem_a), Box::new(mem_b), Box::new(fold)];
    let wired = Wired::new(regions, alloc::vec![0, 1, 2], sigma, Fp::from_u64(5), Fp::from_u64(7));
    let witness = wired.trace(&[open_a, open_b, fold_trace]);
    let proof = stark_prove(&wired, &witness, QUERIES);
    assert!(stark_verify(&wired, &proof, QUERIES), "a fold on two committed openings was rejected");
}

#[test]
fn a_fold_with_an_uncommitted_second_input_is_rejected() {
    // The first input is committed but the second is a value no opening committed.
    let (beta, a, b, x_inv, dir, final_value, log_layers, n_folds) = trace_fold_data(6);
    let (open_a, mem_a, _) = opening_of_scalar(a[0], 2);
    let (open_b, mem_b, _) = opening_of_scalar(b[0] + Fp::ONE, 2); // commits a wrong b
    let fold = TraceFold::new(log_layers, n_folds, x_inv, dir, final_value);
    let fold_trace = fold.trace(&beta, &a, &b);

    let mem_h = mem_a.rows();
    let fold_off = 2 * mem_h;
    let k = 3usize;
    let span = (2 * mem_h + (1usize << log_layers)).next_power_of_two();
    let mut sigma: Vec<usize> = (0..span * k).collect();
    sigma.swap(0, fold_off * k + 1);
    sigma.swap(mem_h * k, fold_off * k + 2);

    let regions: Vec<Box<dyn Air>> = alloc::vec![Box::new(mem_a), Box::new(mem_b), Box::new(fold)];
    let wired = Wired::new(regions, alloc::vec![0, 1, 2], sigma, Fp::from_u64(5), Fp::from_u64(7));
    let witness = wired.trace(&[open_a, open_b, fold_trace]);
    let proof = stark_prove(&wired, &witness, QUERIES);
    assert!(
        !stark_verify(&wired, &proof, QUERIES),
        "a fold on an uncommitted second input verified"
    );
}

/// A minimal single Merkle opening committing the scalar `v` (two leaves, two
/// rounds), so per-layer openings stay cheap to fuse.
pub(super) fn small_opening_of_scalar(v: Fp) -> (Vec<Fp>, MultiMembership) {
    let log_rounds = 1u32;
    let hasher = Poseidon::new(log_rounds, [Fp::ZERO; RATE]);
    let mut leaves = merkle_leaves(2);
    leaves[0] = [v, Fp::ZERO, Fp::ZERO, Fp::ZERO];
    let tree = PoseidonMerkleTree::commit(&hasher, &leaves);
    let opening = opening_at(&tree, &leaves, 0);
    let mem = MultiMembership::new(hasher, log_rounds, alloc::vec![opening]);
    let trace = mem.trace();
    (trace, mem)
}

/// Fuse one opening per fold layer, each committing that layer's opened value,
/// and wire each to the fold's input at that layer. `wrong_layer`, if set, makes
/// that layer's opening commit a value the fold did not fold.
pub(super) fn per_layer_monolith(query: usize, wrong_layer: Option<usize>) -> (Wired, Vec<Fp>) {
    let (beta, a, b, x_inv, dir, final_value, log_layers, n_folds) = trace_fold_data(query);
    let mut regions: Vec<Box<dyn Air>> = Vec::new();
    let mut traces: Vec<Vec<Fp>> = Vec::new();
    let mut open_rows: Vec<usize> = Vec::new();
    let mut acc = 0usize;
    for (m, &am) in a.iter().enumerate().take(n_folds) {
        let scalar = if wrong_layer == Some(m) { am + Fp::ONE } else { am };
        let (tr, mem) = small_opening_of_scalar(scalar);
        open_rows.push(acc);
        acc += mem.rows();
        traces.push(tr);
        regions.push(Box::new(mem));
    }
    let fold_off = acc;
    let fold = TraceFold::new(log_layers, n_folds, x_inv, dir, final_value);
    traces.push(fold.trace(&beta, &a, &b));
    regions.push(Box::new(fold));
    acc += 1usize << log_layers;

    let span = acc.next_power_of_two();
    let k = 2usize;
    let mut sigma: Vec<usize> = (0..span * k).collect();
    for (m, &orow) in open_rows.iter().enumerate() {
        // opening m's leaf (col 0) <-> fold input at layer m (col 1)
        sigma.swap(orow * k, (fold_off + m) * k + 1);
    }
    let wired = Wired::new(regions, alloc::vec![0, 1], sigma, Fp::from_u64(5), Fp::from_u64(7));
    let witness = wired.trace(&traces);
    (wired, witness)
}

#[test]
fn every_layer_input_is_a_committed_opening() {
    // The full per-query opening structure: every layer's fold input is bound to
    // a committed Merkle opening at that layer, not just the first.
    let (wired, witness) = per_layer_monolith(6, None);
    let proof = stark_prove(&wired, &witness, QUERIES);
    assert!(stark_verify(&wired, &proof, QUERIES), "per-layer committed openings rejected");
}

#[test]
fn an_uncommitted_layer_input_is_rejected() {
    // One layer folds a value its opening did not commit; the proof fails.
    let (wired, witness) = per_layer_monolith(6, Some(2));
    let proof = stark_prove(&wired, &witness, QUERIES);
    assert!(!stark_verify(&wired, &proof, QUERIES), "an uncommitted layer input verified");
}
