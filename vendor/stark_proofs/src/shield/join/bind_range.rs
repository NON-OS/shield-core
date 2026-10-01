// NONOS Operating System (AGPL-3.0-or-later)

use super::bind::Layout;
use super::terms::balance_shape;
use crate::crypto::stark::air::LimbRange;
use crate::shield::wire_class::{pair, Class};
use alloc::vec::Vec;

/// Each cell the balance region bounds is the first cell of its segment in the
/// range region, so the segment's bits decompose that cell and no other.
pub fn range_classes(l: &Layout) -> Vec<Class> {
    let cells = balance_shape().ranged();
    let seg = LimbRange { bits: cells.iter().map(|&(_, _, b)| b).collect(), values: Vec::new() };
    cells
        .iter()
        .enumerate()
        .map(|(k, &(row, col, _))| pair(l.balance + row, col, l.range + seg.start(k), 0))
        .collect()
}
