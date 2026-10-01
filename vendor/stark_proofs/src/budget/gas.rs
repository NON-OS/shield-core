// NONOS Operating System (AGPL-3.0-or-later)
//! What a verifier's work costs, as a model with named coefficients.
//!
//! This is a structural estimate and it says so. Every coefficient is priced
//! from an EVM opcode cost and an operation count, and every one of them is
//! wrong by some factor that only a profile can supply. What the model is for
//! is not predicting a number, it is ranking parameter points against each
//! other, where a coefficient that is uniformly off cancels.
//!
//! The one thing it deliberately does not include is memory expansion. A
//! verifier that materialises per query has a cost quadratic in query count
//! (`evm::memory_gas_over_queries`), and the whole point of the streaming
//! rewrite is that the term goes to zero. Adding it here would bake today's
//! implementation into a model meant to outlive it.

use super::super::proof_wire::Layout;

/// Coefficients, each with the arithmetic that produced it. Defaults are
/// estimates; a profile replaces them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CostModel {
    /// One Merkle node: keccak of two 24-byte children is 30 + 6 per word
    /// over two words, plus loading and comparing.
    pub node: u64,
    /// One multiplication in the quadratic extension: three `MULMOD` at 8
    /// gas by Karatsuba, plus additions and reduction.
    pub fp2_mul: u64,
    /// One value of a trace row, loaded from calldata and accumulated.
    pub row_value: u64,
    /// One transition constraint, evaluated at the out-of-domain point. A
    /// degree `d` constraint is about `d` extension multiplications, so this
    /// scales with the AIR's constraint degree rather than being flat.
    pub transition_per_degree: u64,
    /// One DEEP quotient term: a multiply and an accumulate against a
    /// witnessed inverse, so no division.
    pub deep_term: u64,
    /// One FRI layer folded for one query, at radix four.
    pub fold: u64,
    /// Fixed work outside the query loop: the transcript replay, the head,
    /// the grind check, the boundary evaluation.
    pub fixed: u64,
}

impl Default for CostModel {
    fn default() -> CostModel {
        CostModel {
            node: 60,
            fp2_mul: 40,
            row_value: 20,
            transition_per_degree: 40,
            deep_term: 60,
            fold: 500,
            fixed: 200_000,
        }
    }
}

/// What one query costs, broken into the terms that scale differently, so a
/// reader can see which parameter moves which line.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct QueryCost {
    pub merkle: u64,
    pub deep: u64,
    pub transitions: u64,
    pub row: u64,
    pub folds: u64,
    pub horner: u64,
}

impl QueryCost {
    pub fn total(&self) -> u64 {
        self.merkle + self.deep + self.transitions + self.row + self.folds + self.horner
    }
}

/// The Merkle nodes one query opens: four trees at the domain's depth (the
/// region trace, the permutation columns, the composition and the periodic
/// sidecar), plus one path per FRI layer at that layer's depth. The DEEP
/// value has no tree of its own: it is FRI's layer-zero opening.
pub fn nodes_per_query(l: &Layout) -> u64 {
    let non_fri = 4 * l.tree_depth as u64;
    let fri: u64 = (0..l.fri_layers).map(|m| l.fri_depth(m) as u64).sum();
    non_fri + fri
}

/// The cost of one query, given the geometry and the AIR's shape.
///
/// `n_deep` is the number of DEEP quotient terms, `n_transition` the
/// constraint count and `degree` their degree, all of which the parameter set
/// already carries.
pub fn query_cost(
    l: &Layout,
    model: &CostModel,
    n_deep: u64,
    n_transition: u64,
    degree: u64,
    window: u64,
) -> QueryCost {
    QueryCost {
        merkle: nodes_per_query(l) * model.node,
        deep: n_deep * model.deep_term,
        transitions: n_transition * degree * model.transition_per_degree,
        row: l.trace_width as u64 * window * model.row_value,
        folds: l.fri_layers as u64 * model.fold,
        /*
         * FRI stops early and the prover sends the final polynomial's
         * coefficients once, in the head. Every query then evaluates that
         * polynomial at its own final point by Horner, so the head's size
         * turns into per-query work. This is the term that was missing from
         * the first structural floor we published, and it is the largest one.
         */
        horner: l.n_final as u64 * model.fp2_mul,
    }
}

/// Modelled execution gas for a whole verification: the fixed work plus one
/// query cost per query. Linear in query count by construction, which is the
/// shape a streaming verifier has and the shape the profile has to confirm.
pub fn verify_gas(
    l: &Layout,
    model: &CostModel,
    n_deep: u64,
    n_transition: u64,
    degree: u64,
    window: u64,
) -> u64 {
    model.fixed + l.n_queries as u64 * query_cost(l, model, n_deep, n_transition, degree, window).total()
}
