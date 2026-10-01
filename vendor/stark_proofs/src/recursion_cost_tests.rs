// NONOS Operating System (AGPL-3.0-or-later)
//! What private aggregation costs: N separately proved inners in one outer.
//!
//! `batch_shape_tests` measures one inner carrying N intents, which is a prover
//! holding N senders' witnesses. Aggregation without custody is the other
//! shape: each sender proves its own inner, and the outer verifies all of them
//! (`assemble_many`). This prints that outer, uncapped, at the settlement point:
//! its rows, width, the domain it proves over, and the low-degree extension that
//! domain implies. Release tier: every inner is proved for real.

use crate::crypto::stark::air::{domain_params_blown, Air};
use crate::recursion_assembly::build::{assemble_many_wired, Wiring};
use crate::recursion_assembly::inner;
use crate::shield_params::settlement;
use std::time::Instant;

#[test]
#[ignore = "release tier: proves each inner for real and assembles the uncapped outer"]
fn print_the_outer_cost_per_separate_inner() {
    let h = inner::hasher();
    for n in [1usize, 2] {
        let t = Instant::now();
        let inners = (0..n).map(|_| inner::shield_join_split(&h)).collect();
        let agg = assemble_many_wired(&h, inners, usize::MAX, Wiring::Chained);
        let w = &agg.wired;
        let (log_n, _) = domain_params_blown(w, settlement::EXTRA_BLOWUP_BITS);
        let cells = (1u64 << log_n) * w.trace_width() as u64;
        println!(
            "inners {n}: span {} rows, trace 2^{}, width {}, domain 2^{log_n}, LDE {} cells = {:.1} GB at 8 bytes, assembled in {:?}",
            agg.lays[0].span,
            w.log_trace_len(),
            w.trace_width(),
            cells,
            cells as f64 * 8.0 / 1e9,
            t.elapsed()
        );
    }
}

/// Where the rows of one inner verification go. The regions stack in kind
/// order, the shared kinds once and the per-query kinds once per inner query,
/// so summing each kind over its instances says which part of the verifier
/// the rows pay for, and the width split says what the columns are.
#[test]
#[ignore = "release tier: proves one inner for real and assembles the uncapped outer"]
fn print_the_rows_of_one_inner_by_region() {
    let h = inner::hasher();
    let one = vec![inner::shield_join_split(&h)];
    let agg = assemble_many_wired(&h, one, usize::MAX, Wiring::Chained);
    let w = &agg.wired;
    let lay = &agg.lays[0];
    let shapes = w.region_shapes();
    let bodies = &agg.kind_bodies;
    // shapes = shared + n_q * per_q, bodies = shared + per_q.
    let per_q = (shapes.len() - bodies.len()) / (lay.n_q - 1);
    let shared = bodies.len() - per_q;
    assert_eq!(
        shapes.len(),
        shared + lay.n_q * per_q,
        "regions and kinds disagree"
    );
    let kind_of = |i: usize| {
        if i < shared {
            i
        } else {
            shared + (i - shared) % per_q
        }
    };

    let mut rows = vec![0usize; bodies.len()];
    let mut width = vec![0usize; bodies.len()];
    let mut count = vec![0usize; bodies.len()];
    for (i, &(wd, r)) in shapes.iter().enumerate() {
        let k = kind_of(i);
        rows[k] += r;
        width[k] = width[k].max(wd);
        count[k] += 1;
    }
    let total: usize = rows.iter().sum();
    println!(
        "span {} rows, {} regions, {} inner queries",
        lay.span,
        shapes.len(),
        lay.n_q
    );
    println!("kind | body | role | instances | rows each | rows | share | width");
    for (k, &(body, role)) in bodies.iter().enumerate() {
        println!(
            "{k} | {body} | {role} | {} | {} | {} | {:.2}% | {}",
            count[k],
            rows[k] / count[k],
            rows[k],
            100.0 * rows[k] as f64 / total as f64,
            width[k]
        );
    }
    println!(
        "inner: fri domain 2^{}, rounds per op {}, fri depth {}, openings {}, trace auth depth {}, perm auth depth {}, folds {}, final {}, width {}",
        lay.log_n, lay.l, lay.depth, lay.n_open, lay.ta_depth, lay.ra_depth, lay.n_folds, lay.n_final, lay.width_inner
    );
    println!(
        "outer width: regions {}, products {}, mask {}, wired {}, total {}",
        w.region_width(),
        w.product_columns(),
        w.mask_columns(),
        w.wired_columns().len(),
        w.trace_width()
    );
}
