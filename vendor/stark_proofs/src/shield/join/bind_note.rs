// NONOS Operating System (AGPL-3.0-or-later)

use super::bind::Layout;
use crate::crypto::stark::air::RATE;
use crate::shield::note::{cm_row, note_edges, public_row};
use crate::shield::wire_class::{pair, Class};
use alloc::vec::Vec;

/// Each note stays a chained compress tree, its committed value limbs are the
/// balance row's limbs, and each spent note is the leaf both trees walk from.
pub fn note_classes(l: &Layout) -> Vec<Class> {
    let mut c = Vec::new();
    for (i, &base) in l.note.iter().enumerate() {
        for sw in note_edges(base, l.span_op) {
            c.push(pair(sw.0, sw.1, sw.2, sw.3));
        }
        let bal = l.balance + i;
        let public = public_row(base, l.span_op);
        c.push(pair(bal, 1, public, 0));
        c.push(pair(bal, 2, public, 1));
    }
    for (i, &m) in l.member.iter().enumerate() {
        let cm = cm_row(l.note[i], l.span_op);
        let lc = l.leaf_col[i];
        for k in 0..RATE {
            c.push(pair(cm, k, m, lc + k));
        }
    }
    for (i, &a) in l.assoc.iter().enumerate() {
        let cm = cm_row(l.note[i], l.span_op);
        let lc = l.assoc_col[i];
        for k in 0..RATE {
            c.push(pair(cm, k, a, lc + k));
        }
    }
    c
}
