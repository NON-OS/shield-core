// NONOS Operating System (AGPL-3.0-or-later)

use crate::crypto::stark::air::RATE;
use crate::shield::note::POOL_LOG_ROUNDS;
use alloc::vec::Vec;

pub fn spend_pk_row(base: usize) -> usize {
    base + (1usize << POOL_LOG_ROUNDS)
}

pub fn absorbed_cm_row(base: usize, span_op: usize) -> usize {
    base + 2 * span_op
}

/// Every lane of the key hierarchy's absorbed words that is zero, in the
/// assembly's coordinates.
///
/// The two domain words are `tag(v)`, which is the value in lane zero and zero
/// above it, and the position word's lanes two and up are zero whether the input
/// is live or dead. Before this they were pinned one boundary per lane, which is
/// ten boundaries a region to say three distinct things. One class over all of
/// them plus one boundary anchoring the class to zero says the same thing, and
/// each inner boundary costs the outer ten DEEP terms where the class costs
/// nothing new: these columns already carry the commitment absorbed at the third
/// compression, so they are wired either way.
///
/// Lane one of the position word is not here. It says live or dead and the live
/// gate is the only region that knows which, so it is bound there and pinning it
/// to zero would refuse every dummy.
///
/// Lane zero of the position word is not here either: it is the position the
/// path recovered and `index_classes` binds it.
pub fn domain_zero_cells(base: usize, span_op: usize) -> Vec<(usize, usize)> {
    let mut cells = Vec::with_capacity(3 * RATE);
    for o in [0usize, 1] {
        for c in 1..RATE {
            cells.push((base + o * span_op, RATE + c));
        }
    }
    for c in 2..RATE {
        cells.push((base + 3 * span_op, RATE + c));
    }
    cells
}

pub fn nullifier_edges(base: usize, span_op: usize) -> Vec<(usize, usize, usize, usize)> {
    let l = 1usize << POOL_LOG_ROUNDS;
    let first = |o: usize| base + o * span_op;
    let root = |o: usize| base + o * span_op + l;
    let mut sw = Vec::with_capacity(3 * RATE);
    for c in 0..RATE {
        sw.push((first(0), c, first(1), c));
        sw.push((root(1), c, first(2), c));
        sw.push((root(2), c, first(3), c));
    }
    sw
}
