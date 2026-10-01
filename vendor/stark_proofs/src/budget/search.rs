// NONOS Operating System (AGPL-3.0-or-later)
//! The parameter point as a search rather than a hand-tuned constant.
//!
//! Four points were picked by hand in one day, each right for the reason it
//! was picked and none of them compared against the others under all five
//! budgets at once. This enumerates the space instead: every point that meets
//! the provable soundness floor and fits the byte ceiling and the transaction
//! gas cap, with what each one costs in proving.
//!
//! It changes nothing. It reports. The decision is still a person reading a
//! table, but the table is now complete rather than four rows someone thought
//! of.

use super::super::proof_wire::{Layout, ParamSet};
use super::evm;
use super::gas::{query_cost, CostModel};
use alloc::vec::Vec;

/// The knobs a point may move. Everything else is the circuit and is fixed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Point {
    pub n_queries: u32,
    pub extra_blowup_bits: u32,
    pub grind_bits: u32,
    pub fri_stop_log: u32,
    pub fri_fold_log: u32,
}

/// What a point has to satisfy to be admissible at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Limits {
    /// The provable floor. Not the conjectured figure: a point that needs the
    /// capacity conjecture to reach the floor has not reached it.
    pub min_provable_bits: u32,
    /// The proof size ceiling.
    pub max_bytes: u64,
    /// The most grinding a prover will actually do. Thirty two bits is under
    /// a minute in parallel; forty eight is about 256 CPU-hours, which looks
    /// fine in a table and is not a thing anyone ships.
    pub max_grind_bits: u32,
    /// The largest evaluation domain the prover has memory for.
    pub max_log_domain: u32,
    /// Fold radices the prover actually implements, as log2, inclusive.
    ///
    /// Defaults to exactly the one that exists. A search that returns a point
    /// the prover cannot produce is worse than no search, because it looks
    /// like an answer: the first run of this widened the range and put radix
    /// eight at the top of the table, which is a real result about where the
    /// space is good and not a point anyone can prove today. Widen it
    /// deliberately, and read what comes back as a proposal to implement
    /// something rather than as a point to move to.
    pub fold_log_range: (u32, u32),
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            min_provable_bits: 80,
            max_bytes: 131_072,
            max_grind_bits: 32,
            max_log_domain: 30,
            fold_log_range: (2, 2),
        }
    }
}

/// A point with every budget evaluated.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Evaluated {
    pub point: Point,
    /// The rate exponent, `1 + extra_blowup_bits`. Each query buys this many
    /// bits under the capacity conjecture and half of them provably.
    pub rate_exponent: u32,
    pub provable_bits: u32,
    pub conjectured_bits: u32,
    pub log_domain: u32,
    pub fri_layers: usize,
    pub bytes: u64,
    pub calldata_gas: u64,
    pub execution_budget: u64,
    pub modelled_verify_gas: u64,
    pub headroom: u64,
    /// Proving work relative to the shipped point, in parts per thousand,
    /// from the domain alone. The transform is the dominant term and it is
    /// linearithmic, so this is a ratio of `n log n` rather than of `n`.
    /// Integer rather than a float: this is a no_std crate and a ranking key
    /// that depends on floating point rounding is a ranking key that can
    /// differ between builds.
    pub proving_relative_permille: u64,
}

/// The rate exponent a point proves at. The engine doubles the degree bound
/// and the point's extra blowup raises it again, so the code rate against
/// that bound is `2^-(1 + extra)`.
pub fn rate_exponent(extra_blowup_bits: u32) -> u32 {
    1 + extra_blowup_bits
}

/// Soundness in bits, provable first. Provable uses the Johnson bound, where
/// a query's error is the square root of the rate, so each query buys half
/// the rate exponent. Conjectured uses list decoding to capacity, where a
/// query buys all of it. Grinding adds its bits to either.
pub fn soundness(p: &Point) -> (u32, u32) {
    let r = rate_exponent(p.extra_blowup_bits);
    let provable = p.n_queries * r / 2 + p.grind_bits;
    let conjectured = p.n_queries * r + p.grind_bits;
    (provable, conjectured)
}

/// The DEEP quotient terms a verifier accumulates: the out-of-domain frame,
/// the periodic claims, and the composition itself.
pub fn deep_terms(l: &Layout) -> u64 {
    l.n_ood as u64 + l.n_periodic as u64 + 1
}

/// The parameter set for a point over a fixed circuit.
pub fn params_at(circuit: &ParamSet, p: &Point) -> ParamSet {
    ParamSet {
        n_queries: p.n_queries,
        grind_bits: p.grind_bits,
        extra_blowup_bits: p.extra_blowup_bits,
        fri_stop_log: p.fri_stop_log,
        fri_fold_log: p.fri_fold_log,
        ..*circuit
    }
}

/// Evaluate one point against every budget, or say why it is inadmissible.
pub fn evaluate(
    circuit: &ParamSet,
    p: &Point,
    model: &CostModel,
    limits: &Limits,
) -> Result<Evaluated, &'static str> {
    let (provable_bits, conjectured_bits) = soundness(p);
    if provable_bits < limits.min_provable_bits {
        return Err("below the provable soundness floor");
    }
    if p.grind_bits > limits.max_grind_bits {
        return Err("more grinding than a prover will do");
    }
    if p.fri_fold_log < limits.fold_log_range.0 || p.fri_fold_log > limits.fold_log_range.1 {
        return Err("a fold radix the prover does not implement");
    }
    let params = params_at(circuit, p);
    let log_domain = Layout::log_domain_of(&params);
    if log_domain > limits.max_log_domain {
        return Err("evaluation domain beyond the prover's memory");
    }
    let (fri_layers, _) = Layout::fri_shape(&params);
    if fri_layers == 0 {
        return Err("no FRI layer, so no query checks anything");
    }
    let l = Layout::of(&params);
    let bytes = l.end as u64;
    if bytes > limits.max_bytes {
        return Err("over the proof size ceiling");
    }
    let tokens = evm::tokens_estimated(bytes);
    let calldata_gas = evm::GAS_PER_TOKEN * tokens;
    let Some(execution_budget) = evm::execution_budget(tokens) else {
        return Err("the calldata alone exceeds the transaction cap");
    };
    let q = query_cost(
        &l,
        model,
        deep_terms(&l),
        circuit.num_transition as u64,
        circuit.constraint_degree as u64,
        circuit.window_size as u64,
    );
    let modelled_verify_gas = model.fixed + p.n_queries as u64 * q.total();
    if modelled_verify_gas > execution_budget {
        return Err("modelled verification does not fit the execution budget");
    }
    /*
     * Proving is dominated by transforms over the evaluation domain, which
     * are linearithmic, so a domain one bit smaller is a little better than
     * half the work. Reported against the shipped point so the column reads
     * as a factor rather than an absolute nobody can check.
     */
    let n = |k: u32| (1u64 << k) * k as u64;
    let proving_relative_permille = n(log_domain) * 1000 / n(SHIPPED_LOG_DOMAIN);

    Ok(Evaluated {
        point: *p,
        rate_exponent: rate_exponent(p.extra_blowup_bits),
        provable_bits,
        conjectured_bits,
        log_domain,
        fri_layers,
        bytes,
        calldata_gas,
        execution_budget,
        modelled_verify_gas,
        headroom: execution_budget - modelled_verify_gas,
        proving_relative_permille,
    })
}

/// The evaluation domain of the shipped point, the baseline `proving_relative`
/// is measured against.
pub const SHIPPED_LOG_DOMAIN: u32 = 29;

/// Every admissible point in range, cheapest to prove first and, among equals,
/// the one with the most gas headroom.
pub fn search(circuit: &ParamSet, model: &CostModel, limits: &Limits) -> Vec<Evaluated> {
    let mut out = Vec::new();
    for n_queries in 1u32..=64 {
        for extra_blowup_bits in 0u32..=12 {
            for grind_bits in [0u32, 16, 20, 24, 28, 32] {
                if grind_bits > limits.max_grind_bits {
                    continue;
                }
                for fri_stop_log in 0u32..=12 {
                    for fri_fold_log in limits.fold_log_range.0..=limits.fold_log_range.1 {
                        let p = Point {
                            n_queries,
                            extra_blowup_bits,
                            grind_bits,
                            fri_stop_log,
                            fri_fold_log,
                        };
                        if let Ok(e) = evaluate(circuit, &p, model, limits) {
                            out.push(e);
                        }
                    }
                }
            }
        }
    }
    out.sort_by(|a, b| {
        a.log_domain
            .cmp(&b.log_domain)
            .then(b.headroom.cmp(&a.headroom))
            .then(a.bytes.cmp(&b.bytes))
            .then(a.point.fri_stop_log.cmp(&b.point.fri_stop_log))
    });
    /*
     * Several stop parameters give the same layer count, and a layer count
     * fixes the whole geometry, so they are one point wearing different
     * labels. Collapsing them keeps the table a list of choices rather than a
     * list of spellings; the lowest stop survives because it is the one that
     * says what the geometry actually is.
     */
    out.dedup_by(|a, b| {
        a.point.n_queries == b.point.n_queries
            && a.point.grind_bits == b.point.grind_bits
            && a.log_domain == b.log_domain
            && a.fri_layers == b.fri_layers
            && a.bytes == b.bytes
    });
    out
}
