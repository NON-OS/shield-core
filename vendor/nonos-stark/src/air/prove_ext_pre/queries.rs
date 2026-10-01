// NONOS Operating System (AGPL-3.0-or-later)

//! Opening the queries on the preprocessed path. Each sampled position reveals the trace,
//! composition, and DEEP values as on the plain path, and alongside them the opened row of the
//! baked periodic schedule with its path to the baked root. The verifier checks that opened
//! row against the root it holds as a constant, so the schedule is authenticated per query
//! without the prover ever recomputing it.

use super::super::super::field::{Fp, Fp2};
use super::super::super::merkle::MerkleTree;
use super::super::prove_ext::{eval_base, Domain};
use super::super::wire::types_ext::StarkQueryExt;
use super::super::wire::types_ext_pre::PeriodicOpeningExt;
use alloc::vec::Vec;

/// Open everything at FRI's positions, the periodic sidecar included. The DEEP
/// value is FRI's own layer-zero opening there. Trace and periodic values are
/// evaluated from coefficients on demand; the trees hold the commitments.
#[allow(clippy::too_many_arguments)]
pub(super) fn open(
    positions: &[usize],
    d: &Domain,
    trace: &[Vec<Fp>],
    trace_tree: &MerkleTree,
    periodic: &[Vec<Fp>],
    periodic_tree: &MerkleTree,
    comp_d: &[Fp2],
    comp_tree: &MerkleTree,
) -> (Vec<StarkQueryExt>, Vec<PeriodicOpeningExt>) {
    let mut queries = Vec::with_capacity(positions.len());
    let mut openings = Vec::with_capacity(positions.len());
    for &p in positions {
        let x_p = d.shift * d.omega.pow(p as u64);
        queries.push(StarkQueryExt {
            trace: trace.iter().map(|cf| eval_base(cf, x_p)).collect(),
            trace_path: trace_tree.open(p),
            comp: comp_d[p],
            comp_path: comp_tree.open(p),
        });
        openings.push(PeriodicOpeningExt {
            row: periodic.iter().map(|cf| eval_base(cf, x_p)).collect(),
            path: periodic_tree.open(p),
        });
    }
    (queries, openings)
}

/// The same walk when the trace was committed in two rounds.
///
/// A query's row is still one row. What changes is that its region half
/// authenticates under the first round's root and its permutation half under
/// the second, so each position yields a second path.
#[allow(clippy::too_many_arguments)]
pub(super) fn open_rounds(
    positions: &[usize],
    d: &Domain,
    trace: &[Vec<Fp>],
    region_open: &dyn Fn(usize) -> Vec<[u8; 32]>,
    perm_open: &dyn Fn(usize) -> Vec<[u8; 32]>,
    periodic: &[Vec<Fp>],
    periodic_open: &dyn Fn(usize) -> Vec<[u8; 32]>,
    comp_d: &[Fp2],
    comp_open: &dyn Fn(usize) -> Vec<[u8; 32]>,
) -> (
    Vec<StarkQueryExt>,
    Vec<PeriodicOpeningExt>,
    Vec<Vec<[u8; 32]>>,
) {
    let mut queries = Vec::with_capacity(positions.len());
    let mut openings = Vec::with_capacity(positions.len());
    let mut perm_paths = Vec::with_capacity(positions.len());
    for &p in positions {
        let x_p = d.shift * d.omega.pow(p as u64);
        queries.push(StarkQueryExt {
            trace: trace.iter().map(|cf| eval_base(cf, x_p)).collect(),
            trace_path: region_open(p),
            comp: comp_d[p],
            comp_path: comp_open(p),
        });
        perm_paths.push(perm_open(p));
        openings.push(PeriodicOpeningExt {
            row: periodic.iter().map(|cf| eval_base(cf, x_p)).collect(),
            path: periodic_open(p),
        });
    }
    (queries, openings, perm_paths)
}
