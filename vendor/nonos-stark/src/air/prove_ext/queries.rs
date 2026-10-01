// NONOS Operating System (AGPL-3.0-or-later)

//! Opening the consistency queries. At each sampled position the prover reveals the trace,
//! composition, and DEEP values with their Merkle paths, so the verifier can check that the
//! opened values are the committed ones and that the DEEP quotient the values imply matches the
//! opened DEEP value. `eval_base` recovers a column's value at a query point from its
//! coefficients by Horner, so the opening reads the streamed trace without a stored extension.

use super::super::super::field::{Fp, Fp2};
use super::super::super::merkle::MerkleTree;
use super::super::wire::types_ext::StarkQueryExt;
use super::setup::Domain;
use alloc::vec::Vec;

/// A column at one domain point, from its coefficients. Horner gives exactly
/// the value the extension would have held: same polynomial, same point, exact
/// field arithmetic.
pub(in crate::air) fn eval_base(coeffs: &[Fp], x: Fp) -> Fp {
    let mut acc = Fp::ZERO;
    for c in coeffs.iter().rev() {
        acc = acc * x + *c;
    }
    acc
}

/// Open everything at FRI's positions. The DEEP value is FRI's own layer-zero
/// opening there, so only the trace and the composition are opened here. The
/// trace values are evaluated on demand; the trees already hold the commitments.
pub(super) fn open(
    positions: &[usize],
    d: &Domain,
    trace: &[Vec<Fp>],
    trace_tree: &MerkleTree,
    comp_d: &[Fp2],
    comp_tree: &MerkleTree,
) -> Vec<StarkQueryExt> {
    let mut queries = Vec::with_capacity(positions.len());
    for &p in positions {
        let x_p = d.shift * d.omega.pow(p as u64);
        let trace_vals: Vec<Fp> = trace.iter().map(|cf| eval_base(cf, x_p)).collect();
        queries.push(StarkQueryExt {
            trace: trace_vals,
            trace_path: trace_tree.open(p),
            comp: comp_d[p],
            comp_path: comp_tree.open(p),
        });
    }
    queries
}
