// NONOS Operating System (AGPL-3.0-or-later)
//! The budget arithmetic is checked against the shipped artifact and against
//! the two published EIPs. A model nobody can check is an opinion.

use super::super::proof_wire::{Layout, ParamSet};
use super::evm;
use super::gas::{nodes_per_query, query_cost, CostModel};
use super::search::{deep_terms, evaluate, rate_exponent, search, soundness, Limits, Point};

fn circuit() -> ParamSet {
    ParamSet {
        n_queries: 12,
        grind_bits: 32,
        extra_blowup_bits: 7,
        fri_fold_log: 2,
        fri_stop_log: 8,
        digest_bytes: 24,
        trace_width: 41,
        n_periodic: 119,
        log_trace_len: 18,
        constraint_degree: 8,
        window_size: 2,
        num_transition: 37,
        n_boundary: 723,
        coset_shift: 7,
        commit_grind_bits: 0,
        grind_chunks: 1,
    }
}

fn shipped_point() -> Point {
    Point {
        n_queries: 12,
        extra_blowup_bits: 7,
        grind_bits: 32,
        fri_stop_log: 8,
        fri_fold_log: 2,
    }
}

/// The transaction arithmetic reproduces the shipped artifact's budget
/// exactly, from its measured zero and nonzero byte counts.
#[test]
fn the_shipped_artifact_reproduces_its_transaction_budget() {
    let t = evm::tokens(2_503, 109_933);
    assert_eq!(t, 442_235, "EIP-7623 tokens");
    assert_eq!(evm::GAS_PER_TOKEN * t, 1_768_940, "calldata gas");
    assert_eq!(evm::execution_budget(t), Some(14_987_276), "execution budget");
    assert_eq!(
        evm::BASE_TX_GAS + evm::GAS_PER_TOKEN * t + 14_987_276,
        evm::TX_GAS_CAP,
        "base plus calldata plus budget is the whole cap"
    );
    // The floor branch is far below the standard branch here, which is why a
    // verifier prices on the standard one. A point where that flipped would
    // be priced wrongly by anything that assumed it.
    assert!(evm::FLOOR_GAS_PER_TOKEN * t < evm::GAS_PER_TOKEN * t + 14_987_276);
}

/// The estimated token count from length alone lands on the measured one.
/// It is an estimate and this says how good it is rather than pretending.
#[test]
fn the_token_estimate_is_close_on_the_artifact_it_was_measured_from() {
    let exact = evm::tokens(2_503, 109_933);
    let approx = evm::tokens_estimated(112_436);
    let err = approx.abs_diff(exact);
    assert!(err <= 4, "estimate {approx} against exact {exact}");
}

/// The memory expansion rule, against the value that explains the measured
/// verifier, and against the value a streaming one would have.
#[test]
fn memory_expansion_explains_the_measured_verifier() {
    assert_eq!(evm::memory_gas(165_000), 53_668_828);
    assert_eq!(evm::memory_gas(300), 1_075);
    // The quadratic term is the whole failure: same work per query, and the
    // bill grows with the square of the count.
    let one = evm::memory_gas_over_queries(20_000, 4_531, 1);
    let thirty_two = evm::memory_gas_over_queries(20_000, 4_531, 32);
    assert!(
        thirty_two > 20 * one,
        "quadratic growth: {one} at one query against {thirty_two} at thirty two"
    );
}

/// Soundness, both regimes, at the shipped point. The provable figure is the
/// one the floor is set against.
#[test]
fn the_shipped_point_is_eighty_provable_bits() {
    let p = shipped_point();
    assert_eq!(rate_exponent(p.extra_blowup_bits), 8);
    let (provable, conjectured) = soundness(&p);
    assert_eq!(provable, 80, "12 * 8 / 2 + 32, by the Johnson bound");
    assert_eq!(conjectured, 128, "12 * 8 + 32, under the capacity conjecture");
}

/// The geometry the cost model reads is the artifact's geometry.
#[test]
fn the_query_shape_matches_the_shipped_artifact() {
    let l = Layout::of(&circuit());
    assert_eq!(nodes_per_query(&l), 248, "four trees at 29 plus six FRI paths");
    assert_eq!(deep_terms(&l), 202, "the frame, the periodic claims, the composition");
    assert_eq!(l.n_final, 512, "the final polynomial the Horner term evaluates");
}

/// The model is a sum of named terms, and the terms are the ones documented.
/// This pins the decomposition rather than the total, because the total is an
/// estimate and the decomposition is the claim.
#[test]
fn the_cost_model_decomposes_as_documented() {
    let l = Layout::of(&circuit());
    let m = CostModel::default();
    let c = circuit();
    let q = query_cost(
        &l,
        &m,
        deep_terms(&l),
        c.num_transition as u64,
        c.constraint_degree as u64,
        c.window_size as u64,
    );
    assert_eq!(q.merkle, 248 * 60);
    assert_eq!(q.deep, 202 * 60);
    assert_eq!(q.transitions, 37 * 8 * 40);
    assert_eq!(q.row, 41 * 2 * 20);
    assert_eq!(q.folds, 6 * 500);
    assert_eq!(q.horner, 512 * 40, "the term the first published floor omitted");
    assert_eq!(q.total(), 63_960);
    // Whatever the coefficients turn out to be, the modelled work has to be
    // a small fraction of the budget or none of this was worth doing.
    let total = m.fixed + 12 * q.total();
    assert_eq!(total, 967_520);
    assert!(total * 10 < 14_987_276, "modelled work is under a tenth of the budget");
}

/// The shipped point is admissible, and the search finds it.
#[test]
fn the_shipped_point_is_admissible_and_the_search_contains_it() {
    let c = circuit();
    let m = CostModel::default();
    let lim = Limits::default();
    let e = evaluate(&c, &shipped_point(), &m, &lim).expect("the shipped point must be admissible");
    assert_eq!(e.bytes, 103_820, "112,436 at format 4");
    assert_eq!(e.log_domain, 29);
    assert_eq!(e.fri_layers, 6);
    assert_eq!(e.provable_bits, 80);
    /*
     * The nonzero ratio is calibrated from the 112,436-byte artifact, where
     * the estimate was the measurement: 14,987,276. At format 5 the same
     * point is 103,820 bytes, so this is the estimate at that length, not a
     * measurement, and it carries the calibration's uncertainty like every
     * other length in the search. Fewer calldata bytes leave more of the cap
     * for execution.
     */
    assert_eq!(e.execution_budget, 15_122_840, "the budget at format 5's length");
    assert_eq!(e.proving_relative_permille, 1000, "the baseline is itself");

    let all = search(&c, &m, &lim);
    assert!(
        all.iter().any(|x| x.point == shipped_point()),
        "the search must contain the point we ship"
    );
    // Sorted cheapest to prove first, so the head of the list is never worse
    // to prove than the point we picked by hand.
    assert!(all[0].log_domain <= e.log_domain);
}

/// Every point the search returns satisfies every limit. A search that
/// returns an inadmissible point is worse than no search, because it looks
/// like an answer.
#[test]
fn every_returned_point_is_admissible() {
    let c = circuit();
    let m = CostModel::default();
    let lim = Limits::default();
    for e in search(&c, &m, &lim) {
        assert!(e.provable_bits >= lim.min_provable_bits, "{e:?}");
        assert!(e.bytes <= lim.max_bytes, "{e:?}");
        assert!(e.point.grind_bits <= lim.max_grind_bits, "{e:?}");
        assert!(e.log_domain <= lim.max_log_domain, "{e:?}");
        assert!(e.fri_layers >= 1, "{e:?}");
        assert!(e.modelled_verify_gas <= e.execution_budget, "{e:?}");
        assert_eq!(e.headroom, e.execution_budget - e.modelled_verify_gas);
    }
}

/// A point that needs the capacity conjecture to clear the floor is refused.
/// This is the rule that keeps the conservative number in charge.
#[test]
fn the_conjectured_figure_cannot_admit_a_point() {
    let c = circuit();
    let m = CostModel::default();
    let lim = Limits::default();
    // Six queries at rate exponent 8 with 32 grinding: 80 conjectured, 56
    // provable. Admissible on the wrong number, refused on the right one.
    let p = Point {
        n_queries: 6,
        extra_blowup_bits: 7,
        grind_bits: 32,
        fri_stop_log: 8,
        fri_fold_log: 2,
    };
    let (provable, conjectured) = soundness(&p);
    assert_eq!((provable, conjectured), (56, 80));
    assert!(evaluate(&c, &p, &m, &lim).is_err());
}

/// The default limits admit only the fold radix the prover implements. The
/// first run of this search ranked radix eight first by a wide margin, which
/// is a real finding about the space and is not a point anyone can prove, and
/// a table that mixes the two is a table that gets acted on wrongly.
#[test]
fn the_default_search_only_returns_points_the_prover_can_produce() {
    let c = circuit();
    let m = CostModel::default();
    let lim = Limits::default();
    assert_eq!(lim.fold_log_range, (2, 2), "radix four, which is what exists");
    for e in search(&c, &m, &lim) {
        assert_eq!(e.point.fri_fold_log, 2, "{e:?}");
    }
    let radix_eight = Point {
        n_queries: 16,
        extra_blowup_bits: 5,
        grind_bits: 32,
        fri_stop_log: 4,
        fri_fold_log: 3,
    };
    assert!(
        evaluate(&c, &radix_eight, &m, &lim).is_err(),
        "an unimplemented radix must not be admissible by default"
    );
    // And it is admissible once someone widens the range deliberately.
    let wide = Limits { fold_log_range: (1, 3), ..lim };
    assert!(evaluate(&c, &radix_eight, &m, &wide).is_ok());
}

/// Stop parameters that give the same layer count give the same geometry, so
/// the table lists them once. A list of spellings is not a list of choices.
#[test]
fn equivalent_points_are_collapsed() {
    let c = circuit();
    let m = CostModel::default();
    let lim = Limits::default();
    let all = search(&c, &m, &lim);
    for w in all.windows(2) {
        let (a, b) = (&w[0], &w[1]);
        assert!(
            !(a.point.n_queries == b.point.n_queries
                && a.point.grind_bits == b.point.grind_bits
                && a.log_domain == b.log_domain
                && a.fri_layers == b.fri_layers
                && a.bytes == b.bytes),
            "two rows for one geometry: {a:?} and {b:?}"
        );
    }
}
