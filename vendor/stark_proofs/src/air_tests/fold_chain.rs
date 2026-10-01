// NONOS Operating System (AGPL-3.0-or-later)
//! The fold chain over the tower and the faults that break it.

use crate::crypto::stark::air::{
    stark_prove, stark_verify, Air,
    Squaring, TraceFold, Wired,
};
use crate::crypto::stark::field::Fp;
use alloc::boxed::Box;

extern crate alloc;
use alloc::vec::Vec;
#[allow(unused_imports)]
use super::{fold::*, exec::*, poseidon::*, membership::*, fri::*, monolith::*, ext::*, recursive::*, wired::*, fri_fold::*, fri_fused::*, ext_deep::*, membership_multi::*};

#[test]
fn a_fold_bound_to_its_committed_opening_verifies() {
    // The other half of the monolith's per-query binding: the fold must fold the
    // value the Merkle opening actually committed, not an arbitrary one. The
    // opening commits `a[0]` as its leaf; the wiring binds that leaf cell to the
    // fold's opened value.
    let (beta, a, b, x_inv, dir, final_value, log_layers, n_folds) = trace_fold_data(6);
    let (mem_trace, mem, cells) = opening_of_scalar(a[0], 2);
    assert_eq!(cells[0].1, 0, "the committed scalar should sit in column zero");
    let mem_h = mem.rows();
    let fold = TraceFold::new(log_layers, n_folds, x_inv, dir, final_value);
    let fold_trace = fold.trace(&beta, &a, &b);

    let fold_h = 1usize << log_layers;
    let (k, span) = (2usize, (mem_h + fold_h).next_power_of_two());
    let mut sigma: Vec<usize> = (0..span * k).collect();
    // leaf scalar at (cells[0].0, col 0) <-> fold's opened value at (mem_h, col 1)
    sigma.swap(cells[0].0 * k, mem_h * k + 1);

    let regions: Vec<Box<dyn Air>> = alloc::vec![Box::new(mem), Box::new(fold)];
    let wired = Wired::new(regions, alloc::vec![0, 1], sigma, Fp::from_u64(5), Fp::from_u64(7));
    let witness = wired.trace(&[mem_trace, fold_trace]);
    let proof = stark_prove(&wired, &witness, QUERIES);
    assert!(stark_verify(&wired, &proof, QUERIES), "a fold bound to its opening was rejected");
}

#[test]
fn a_fold_folding_an_uncommitted_value_is_rejected() {
    // The opening commits a different value than the fold folds. Each is
    // internally valid, but the wiring forces the fold to fold exactly what was
    // committed, so the single proof fails.
    let (beta, a, b, x_inv, dir, final_value, log_layers, n_folds) = trace_fold_data(6);
    let (mem_trace, mem, cells) = opening_of_scalar(a[0] + Fp::ONE, 2);
    let mem_h = mem.rows();
    let fold = TraceFold::new(log_layers, n_folds, x_inv, dir, final_value);
    let fold_trace = fold.trace(&beta, &a, &b);

    let fold_h = 1usize << log_layers;
    let (k, span) = (2usize, (mem_h + fold_h).next_power_of_two());
    let mut sigma: Vec<usize> = (0..span * k).collect();
    sigma.swap(cells[0].0 * k, mem_h * k + 1);

    let regions: Vec<Box<dyn Air>> = alloc::vec![Box::new(mem), Box::new(fold)];
    let wired = Wired::new(regions, alloc::vec![0, 1], sigma, Fp::from_u64(5), Fp::from_u64(7));
    let witness = wired.trace(&[mem_trace, fold_trace]);
    let proof = stark_prove(&wired, &witness, QUERIES);
    assert!(!stark_verify(&wired, &proof, QUERIES), "a fold on an uncommitted value verified");
}

#[test]
fn a_full_per_query_verifier_is_one_stark() {
    // The monolith, per query: a challenge source, the Merkle opening of the
    // codeword value, and the in-circuit fold, fused into one trace and verified
    // as a single STARK. The wiring forces the fold to run on exactly the
    // challenge the source produced AND exactly the value the opening committed.
    // One constant-size proof stands for the whole per-query FRI check.
    let (beta, a, b, x_inv, dir, final_value, log_layers, n_folds) = trace_fold_data(6);
    let (mem_trace, mem, cells) = opening_of_scalar(a[0], 2);
    let source = squaring_trace(3, beta[0]); // column zero row 0 holds beta[0]
    let fold = TraceFold::new(log_layers, n_folds, x_inv, dir, final_value);
    let fold_trace = fold.trace(&beta, &a, &b);

    // Region offsets: source [0,8), opening [8,24), fold [24,32).
    let src_h = 1usize << 3;
    let mem_h = mem.rows();
    let fold_off = src_h + mem_h;
    let (k, span) = (2usize, (src_h + mem_h + (1usize << log_layers)).next_power_of_two());
    let mut sigma: Vec<usize> = (0..span * k).collect();
    // source.beta (row 0, col 0) <-> fold.beta (fold_off, col 0)
    sigma.swap(0, fold_off * k);
    // opening leaf (src_h + cells[0].0, col 0) <-> fold.a (fold_off, col 1)
    sigma.swap((src_h + cells[0].0) * k, fold_off * k + 1);

    let regions: Vec<Box<dyn Air>> =
        alloc::vec![Box::new(Squaring { log_t: 3, seed: beta[0] }), Box::new(mem), Box::new(fold)];
    let wired = Wired::new(regions, alloc::vec![0, 1], sigma, Fp::from_u64(5), Fp::from_u64(7));
    let witness = wired.trace(&[source, mem_trace, fold_trace]);
    let proof = stark_prove(&wired, &witness, QUERIES);
    assert!(stark_verify(&wired, &proof, QUERIES), "the fused per-query verifier was rejected");
}

#[test]
fn a_per_query_verifier_rejects_a_wrong_challenge() {
    // Same fused per-query verifier, but the source produces a challenge the fold
    // did not use. One region disagrees on a wired cell, so the whole proof fails.
    let (beta, a, b, x_inv, dir, final_value, log_layers, n_folds) = trace_fold_data(6);
    let (mem_trace, mem, cells) = opening_of_scalar(a[0], 2);
    let source = squaring_trace(3, beta[0] + Fp::ONE); // wrong challenge
    let fold = TraceFold::new(log_layers, n_folds, x_inv, dir, final_value);
    let fold_trace = fold.trace(&beta, &a, &b);

    let src_h = 1usize << 3;
    let mem_h = mem.rows();
    let fold_off = src_h + mem_h;
    let (k, span) = (2usize, (src_h + mem_h + (1usize << log_layers)).next_power_of_two());
    let mut sigma: Vec<usize> = (0..span * k).collect();
    sigma.swap(0, fold_off * k);
    sigma.swap((src_h + cells[0].0) * k, fold_off * k + 1);

    let regions: Vec<Box<dyn Air>> = alloc::vec![
        Box::new(Squaring { log_t: 3, seed: beta[0] + Fp::ONE }),
        Box::new(mem),
        Box::new(fold)
    ];
    let wired = Wired::new(regions, alloc::vec![0, 1], sigma, Fp::from_u64(5), Fp::from_u64(7));
    let witness = wired.trace(&[source, mem_trace, fold_trace]);
    let proof = stark_prove(&wired, &witness, QUERIES);
    assert!(
        !stark_verify(&wired, &proof, QUERIES),
        "a per-query verifier accepted a wrong challenge"
    );
}

#[test]
fn a_per_query_verifier_rejects_a_wrong_opening() {
    // The opening commits a value the fold did not fold. The proof fails.
    let (beta, a, b, x_inv, dir, final_value, log_layers, n_folds) = trace_fold_data(6);
    let (mem_trace, mem, cells) = opening_of_scalar(a[0] + Fp::ONE, 2); // commits a wrong value
    let source = squaring_trace(3, beta[0]);
    let fold = TraceFold::new(log_layers, n_folds, x_inv, dir, final_value);
    let fold_trace = fold.trace(&beta, &a, &b);

    let src_h = 1usize << 3;
    let mem_h = mem.rows();
    let fold_off = src_h + mem_h;
    let (k, span) = (2usize, (src_h + mem_h + (1usize << log_layers)).next_power_of_two());
    let mut sigma: Vec<usize> = (0..span * k).collect();
    sigma.swap(0, fold_off * k);
    sigma.swap((src_h + cells[0].0) * k, fold_off * k + 1);

    let regions: Vec<Box<dyn Air>> =
        alloc::vec![Box::new(Squaring { log_t: 3, seed: beta[0] }), Box::new(mem), Box::new(fold)];
    let wired = Wired::new(regions, alloc::vec![0, 1], sigma, Fp::from_u64(5), Fp::from_u64(7));
    let witness = wired.trace(&[source, mem_trace, fold_trace]);
    let proof = stark_prove(&wired, &witness, QUERIES);
    assert!(
        !stark_verify(&wired, &proof, QUERIES),
        "a per-query verifier accepted a wrong opening"
    );
}

/// Fuse the in-circuit folds of several FRI queries into one trace and wire, per
/// layer, every query's folding challenge into a single cycle: the copy
/// constraint forces all queries to fold on the same challenge set. Returns the
/// wired AIR and its witness. `seeds[q]` seeds query q's codeword, so an honest
/// fan-out uses one seed for all and a dishonest one gives a query a different
/// challenge set.
pub(super) fn multi_query_fanout(queries: &[usize], seeds: &[u64]) -> (Wired, Vec<Fp>) {
    let mut regions: Vec<Box<dyn Air>> = Vec::new();
    let mut traces: Vec<Vec<Fp>> = Vec::new();
    let mut n_folds = 0usize;
    let mut height = 0usize;
    for (&query, &seed) in queries.iter().zip(seeds) {
        let (beta, a, b, x_inv, dir, fv, ll, nf) = trace_fold_data_seeded(query, seed);
        n_folds = nf;
        height = 1usize << ll;
        let fold = TraceFold::new(ll, nf, x_inv, dir, fv);
        traces.push(fold.trace(&beta, &a, &b));
        regions.push(Box::new(fold));
    }

    let q_count = queries.len();
    let span = (q_count * height).next_power_of_two();
    let mut sigma: Vec<usize> = (0..span).collect(); // wired_cols = [0], so cell id == row
                                                     // Per layer, cycle the challenge cell across all queries: q -> q+1 -> ... -> 0.
    for m in 0..n_folds {
        for q in 0..q_count {
            let here = q * height + m;
            let next = ((q + 1) % q_count) * height + m;
            sigma[here] = next;
        }
    }

    let wired = Wired::new(regions, alloc::vec![0], sigma, Fp::from_u64(5), Fp::from_u64(7));
    let witness = wired.trace(&traces);
    (wired, witness)
}

#[test]
fn every_query_folds_on_the_same_challenge_set() {
    // Three FRI queries, folded in one STARK, all wired to a single challenge
    // set. The honest fan-out, where every query used the same transcript
    // challenges, verifies.
    let seed = 0xf01d_1234u64 | 1;
    let (wired, witness) = multi_query_fanout(&[6, 10, 2], &[seed, seed, seed]);
    let proof = stark_prove(&wired, &witness, QUERIES);
    assert!(stark_verify(&wired, &proof, QUERIES), "an honest multi-query fan-out was rejected");
}

#[test]
fn a_query_folding_on_a_different_challenge_set_is_rejected() {
    // One query folded on a different challenge set than the others. Each fold is
    // internally valid, but the wiring forces one shared set, so the single proof
    // fails.
    let seed = 0xf01d_1234u64 | 1;
    let (wired, witness) = multi_query_fanout(&[6, 10, 2], &[seed, 0xdead_beef, seed]);
    let proof = stark_prove(&wired, &witness, QUERIES);
    assert!(
        !stark_verify(&wired, &proof, QUERIES),
        "a query on a different challenge set verified"
    );
}
