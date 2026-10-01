// NONOS Operating System (AGPL-3.0-or-later)

//! Opening the periodic sidecar for a query. The preprocessed path holds the periodic schedule
//! as a baked commitment rather than recomputing it, so a proof carries the claimed periodic
//! values at the out-of-domain point and, per query, one opened row of the committed schedule
//! with its path to the baked root. This is the pass that emits that opened row, the object a
//! recursion binds against the root it holds as a constant instead of half its rows.

use super::super::super::field::Fp;
use super::super::super::poseidon_merkle::PrunedPoseidonTree;
use super::super::periodic_poseidon::{hash_periodic_row, PERIODIC_TREE_CUT};
use super::super::poseidon::{Poseidon, RATE};
use super::super::prove_ext::{eval_base, Domain};
use super::super::wire::types_poseidon_pre::PeriodicOpeningP;
use alloc::vec::Vec;

/// The periodic sidecar for one query: the committed row's values and its path
/// to the baked root, both rebuilt from coefficients. Same values the
/// committed extension held, same path the unpruned tree would return.
pub(super) fn open(
    h: &Poseidon,
    d: &Domain,
    pc: &[Vec<Fp>],
    tree: &PrunedPoseidonTree,
    p: usize,
) -> PeriodicOpeningP {
    let row: Vec<Fp> = pc.iter().map(|cf| eval_base(cf, d.point(p))).collect();
    let chunk = 1usize << PERIODIC_TREE_CUT;
    let base = p & !(chunk - 1);
    let leaves: Vec<[Fp; RATE]> = (0..chunk)
        .map(|o| {
            let r: Vec<Fp> = pc
                .iter()
                .map(|cf| eval_base(cf, d.point(base + o)))
                .collect();
            hash_periodic_row(h, &r)
        })
        .collect();
    PeriodicOpeningP {
        row,
        path: tree.open_with(h, p, &leaves),
    }
}
