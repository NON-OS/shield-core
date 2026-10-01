// NONOS Operating System (AGPL-3.0-or-later)
//! The root bindings, one block per inner query: each of query q's opening
//! checkpoints == the transcript-absorbed root it authenticates under. Openings 0
//! and 1 (FRI leaf, deep) share fri.roots[0] absorbed in the FRI transcript;
//! opening 2 is comp_root, absorbed in the STARK transcript, and the trace
//! chain's terminal digest reaches the one absorbed trace root. The roots are
//! shared; only the opening rows are per-query.
//!
//! A two round inner adds one more: the permutation chain's terminal digest
//! reaches the second root, absorbed after the challenges were squeezed. That
//! absorb sits between the trace root and the batching coefficients, so every
//! operation index past it moves, which is why the composition root's row is
//! measured from the split rather than counted from the head.

use super::super::layout::Layout;
use super::super::sponge::OpCell;
use super::bind::group;
use super::bind::Bind;
use crate::crypto::stark::air::{INJECT, RATE};
use alloc::vec::Vec;

/// An absorbed lane's cell in a transcript region at `off`: the block's
/// first row, the lane's inject column.
pub fn absorbed(lay: &Layout, off: usize, cell: OpCell) -> (usize, usize) {
    (off + cell.0 * lay.l, INJECT + cell.1)
}

/// The columns a chain's terminal digest and four absorbed lanes span.
fn root_cols() -> Vec<usize> {
    let mut v: Vec<usize> = (0..RATE).collect();
    v.extend((0..RATE).map(|j| INJECT + j));
    v
}

pub fn roots(lay: &Layout, out: &mut Vec<Bind>) {
    let l = lay.l;
    for q in 0..lay.n_q {
        let m_off = lay.m_off[q];
        for (o, cell) in lay.ocells[q].iter().enumerate() {
            let cp_row = m_off + cell.0 + lay.depth * l;
            let mut sw: Vec<(usize, usize, usize, usize)> = Vec::new();
            for j in 0..RATE {
                // Openings under the first FRI root, then the composition root.
                let (ar, ac) = if o <= 1 {
                    absorbed(lay, lay.ft_off, lay.cells.fri_root0[j])
                } else {
                    absorbed(lay, 0, lay.cells.comp_root[j])
                };
                sw.push((cp_row, j, ar, ac));
            }
            out.push(group(lay.span, root_cols(), &sw));
        }
        // The trace chain's terminal digest == the absorbed trace root.
        let cp_row = lay.ta_off[q] + lay.ta_depth * l;
        let mut sw: Vec<(usize, usize, usize, usize)> = Vec::new();
        for j in 0..RATE {
            let (ar, ac) = absorbed(lay, 0, lay.cells.trace_root[j]);
            sw.push((cp_row, j, ar, ac));
        }
        out.push(group(lay.span, root_cols(), &sw));

        // The permutation chain's terminal digest == the second absorbed root,
        // which the transcript takes in after the challenges left it.
        if lay.rounds {
            let cp_row = lay.ra_off[q] + lay.ra_depth * l;
            let mut sw: Vec<(usize, usize, usize, usize)> = Vec::new();
            for j in 0..RATE {
                let (ar, ac) = absorbed(lay, 0, lay.cells.perm_root[j]);
                sw.push((cp_row, j, ar, ac));
            }
            out.push(group(lay.span, root_cols(), &sw));
        }
    }
}
