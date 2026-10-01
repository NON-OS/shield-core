// NONOS Operating System (AGPL-3.0-or-later)
//! Shared paths for a two round proof: every tree the launch transcript opens,
//! its leaves, where they sit and how deep the tree is, in one place.
//!
//! A two round proof opens nine trees at the query positions: the four FRI
//! layers, then the trace regions, the permutation columns, the composition
//! and the periodic columns. Each carries one sibling stream
//! (`merkle::multi`) in place of one path per query. `share` builds the
//! streams from a proof with full paths, `fill` puts the full paths back, and
//! the verifier walks them as it always has. The positions are the verifier's
//! own, replayed from the transcript: nothing here trusts an index a proof
//! carries, because a proof carries none.

use super::super::fri::FRI_FOLD_LOG;
use super::super::merkle::multi::{compress, expand};
use super::super::merkle::{
    hash_leaf_ext, hash_leaf_group, hash_leaf_wide, hash_leaf_wide_periodic,
};
use super::wire::types_ext_rounds::StarkProofExtRounds;
use alloc::vec::Vec;

/// The sibling streams of one proof, one per tree, in wire order.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SharedPaths {
    /// One stream per FRI layer, layer zero first.
    pub fri: Vec<Vec<[u8; 32]>>,
    pub trace: Vec<[u8; 32]>,
    pub perm: Vec<[u8; 32]>,
    pub comp: Vec<[u8; 32]>,
    pub periodic: Vec<[u8; 32]>,
}

/// Levels in FRI layer `m`'s tree: one leaf per fold group of the layer, so
/// `FRI_FOLD_LOG` fewer levels than the layer has halvings left.
pub fn fri_layer_depth(log_n: u32, m: usize) -> Option<usize> {
    (log_n as usize).checked_sub((m + 1) * FRI_FOLD_LOG as usize)
}

/// The leaf a query at `q` opens in FRI layer `m`: its position modulo the
/// layer's quarter, which is the tree's leaf count.
pub fn fri_layer_index(q: usize, depth: usize) -> usize {
    q & ((1usize << depth) - 1)
}

/// The streams for `rounds`, whose queries were drawn at `positions` over a
/// `2^log_n` domain. `None` when the proof's counts or path lengths are not
/// the shape, or two queries at one position carry different paths.
pub fn share(rounds: &StarkProofExtRounds, positions: &[usize], log_n: u32) -> Option<SharedPaths> {
    let proof = &rounds.pre.proof;
    let n_q = positions.len();
    if proof.queries.len() != n_q
        || proof.fri.queries.len() != n_q
        || rounds.pre.openings.len() != n_q
        || rounds.perm_paths.len() != n_q
    {
        return None;
    }
    let depth = log_n as usize;
    let n_layers = proof.fri.roots.len();
    let mut fri = Vec::with_capacity(n_layers);
    for m in 0..n_layers {
        let d = fri_layer_depth(log_n, m)?;
        let mut openings = Vec::with_capacity(n_q);
        for (&q, qp) in positions.iter().zip(&proof.fri.queries) {
            openings.push((fri_layer_index(q, d), qp.layers.get(m)?.path.as_slice()));
        }
        fri.push(compress(d, &openings)?);
    }
    let at = |paths: Vec<&[[u8; 32]]>| -> Option<Vec<[u8; 32]>> {
        let openings: Vec<(usize, &[[u8; 32]])> = positions.iter().copied().zip(paths).collect();
        compress(depth, &openings)
    };
    Some(SharedPaths {
        fri,
        trace: at(proof
            .queries
            .iter()
            .map(|q| q.trace_path.as_slice())
            .collect())?,
        perm: at(rounds.perm_paths.iter().map(Vec::as_slice).collect())?,
        comp: at(proof
            .queries
            .iter()
            .map(|q| q.comp_path.as_slice())
            .collect())?,
        periodic: at(rounds
            .pre
            .openings
            .iter()
            .map(|o| o.path.as_slice())
            .collect())?,
    })
}

/// `skeleton` with every path filled in from `shared`, at the verifier's own
/// `positions`. The skeleton's paths are ignored and replaced. `None` when a
/// count is not the shape or a stream does not expand; a stream that expands
/// to paths under the wrong root is left for the path checks to refuse.
pub fn fill(
    skeleton: &StarkProofExtRounds,
    shared: &SharedPaths,
    positions: &[usize],
    log_n: u32,
) -> Option<StarkProofExtRounds> {
    let mut out = skeleton.clone();
    let n_q = positions.len();
    let rw = out.region_width;
    let n_layers = out.pre.proof.fri.roots.len();
    if out.pre.proof.queries.len() != n_q
        || out.pre.proof.fri.queries.len() != n_q
        || out.pre.openings.len() != n_q
        || shared.fri.len() != n_layers
    {
        return None;
    }
    let depth = log_n as usize;

    for m in 0..n_layers {
        let d = fri_layer_depth(log_n, m)?;
        let mut leaves = Vec::with_capacity(n_q);
        for (&q, qp) in positions.iter().zip(&out.pre.proof.fri.queries) {
            leaves.push((fri_layer_index(q, d), hash_leaf_group(&qp.layers.get(m)?.v)));
        }
        let (_, paths) = expand(d, &leaves, &shared.fri[m])?;
        for (qp, path) in out.pre.proof.fri.queries.iter_mut().zip(paths) {
            qp.layers[m].path = path;
        }
    }

    let mut trace = Vec::with_capacity(n_q);
    let mut perm = Vec::with_capacity(n_q);
    let mut comp = Vec::with_capacity(n_q);
    for (&p, qd) in positions.iter().zip(&out.pre.proof.queries) {
        if qd.trace.len() <= rw {
            return None;
        }
        trace.push((p, hash_leaf_wide(&qd.trace[..rw])));
        perm.push((p, hash_leaf_wide(&qd.trace[rw..])));
        comp.push((p, hash_leaf_ext(qd.comp)));
    }
    let periodic: Vec<(usize, [u8; 32])> = positions
        .iter()
        .zip(&out.pre.openings)
        .map(|(&p, op)| (p, hash_leaf_wide_periodic(&op.row)))
        .collect();

    let (_, trace) = expand(depth, &trace, &shared.trace)?;
    let (_, perm) = expand(depth, &perm, &shared.perm)?;
    let (_, comp) = expand(depth, &comp, &shared.comp)?;
    let (_, periodic) = expand(depth, &periodic, &shared.periodic)?;
    for ((qd, t), c) in out.pre.proof.queries.iter_mut().zip(trace).zip(comp) {
        qd.trace_path = t;
        qd.comp_path = c;
    }
    for (op, path) in out.pre.openings.iter_mut().zip(periodic) {
        op.path = path;
    }
    out.perm_paths = perm;
    Some(out)
}
