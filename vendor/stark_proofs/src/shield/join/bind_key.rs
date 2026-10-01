// NONOS Operating System (AGPL-3.0-or-later)

use super::bind::Layout;
use crate::crypto::stark::air::RATE;
use crate::shield::key::{absorbed_cm_row, domain_zero_cells, nullifier_edges, spend_pk_row};
use crate::shield::note::{cm_row, owner_row};
use crate::shield::wire_class::{pair, tie, Class};
use alloc::vec::Vec;

/// The key that retires a note is the key that note committed to, and the
/// commitment it absorbs is the one membership authenticated. Without both, a
/// nullifier is a number the prover chose.
///
/// The last class here is the one that holds the absorbed words' zero lanes
/// together, so a single boundary pinning one of them pins all of them. It
/// replaces eight boundaries a region, and boundaries are what the wrap is
/// priced in: `key::domain_zero_cells` and `shield::test::inner_cost`.
pub fn key_classes(l: &Layout) -> Vec<Class> {
    let mut c = Vec::new();
    for (i, &base) in l.key.iter().enumerate() {
        for sw in nullifier_edges(base, l.key_span[i]) {
            c.push(pair(sw.0, sw.1, sw.2, sw.3));
        }
        let cm = cm_row(l.note[i], l.span_op);
        let owner = owner_row(l.note[i]);
        for k in 0..RATE {
            c.push(pair(spend_pk_row(base), k, owner, k));
            c.push(pair(cm, k, absorbed_cm_row(base, l.key_span[i]), RATE + k));
        }
        c.push(tie(&domain_zero_cells(base, l.key_span[i])));
    }
    c
}
