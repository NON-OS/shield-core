// NONOS Operating System (AGPL-3.0-or-later)
//! The circuit's membership selectors, held to `Shield.Checkpoint` row by row.
//!
//! The Lean proves the checkpoint rule over a schedule: `slotCol`, `cpCol` and
//! `opSel` as functions of the rounds, depth, span, opening count and row.
//! Those proofs say nothing about the circuit unless the circuit's periodic
//! columns are that schedule. This test reads them from the assembled launch
//! join-split and compares every row of every membership instance with the
//! Lean definitions, transcribed term for term in `crate::lean_schedule`. It also holds the
//! instances and their checkpoint rows to the lists the Lean decides
//! (`launchMembers`, `launch_checkpoint_rows`), so neither side can move alone.
#![cfg(not(feature = "launch_v1"))]

use crate::crypto::stark::air::{Air, ShieldRegion};
use crate::crypto::stark::field::Fp;
use crate::lean_schedule::{cp_col, op_sel, slot_col};
use crate::shield::key::Break;
use crate::shield::test::scenario::balanced_deployed;

const WIDTH: usize = 8;

/// `Shield.Checkpoint.launchMembers`: first row, depth, openings.
const LAUNCH_MEMBERS: [(usize, usize, usize); 10] = [
    (8, 1, 2),
    (136, 1, 2),
    (264, 1, 2),
    (392, 1, 2),
    (520, 32, 1),
    (1576, 32, 1),
    (2760, 1, 4),
    (3016, 1, 4),
    (3272, 32, 1),
    (4328, 32, 1),
];

/// `Shield.Checkpoint.launch_checkpoint_rows`.
const LAUNCH_CHECKPOINT_ROWS: [usize; 20] = [
    39, 103, 167, 231, 295, 359, 423, 487, 1543, 2599, 2791, 2855, 2919, 2983, 3047, 3111, 3175,
    3239, 4295, 5351,
];

#[test]
fn the_membership_selectors_are_the_schedule_lean_proves() {
    let js = balanced_deployed(Break::None);
    let air = &js.wired;
    let per = air.periodic_columns();
    let map = air.wired().kind_map();
    let total = 1usize << air.log_trace_len();

    // Region instances in row order, matched to the regions in stacking order.
    let mut runs = Vec::new();
    for k in 0..map.len() {
        let mut r = 0;
        while r < total {
            if per[k][r] == Fp::ONE {
                let s = r;
                while r < total && per[k][r] == Fp::ONE {
                    r += 1;
                }
                runs.push((s, r - 1, k));
            } else {
                r += 1;
            }
        }
    }
    runs.sort_unstable();
    assert_eq!(runs.len(), air.regions().len());

    let mut members = Vec::new();
    let mut checkpoints = Vec::new();
    let mut checked = 0usize;
    for (&(s, e, k), g) in runs.iter().zip(air.regions()) {
        let ShieldRegion::Membership(m) = g else {
            continue;
        };
        let (l, depth, count) = m.schedule();
        assert_eq!(l, 32);
        members.push((s, depth, count));
        let span = (depth + 1) * l;
        let (first, slots, ..) = map[k];
        let (slot, op, cp) = (first + WIDTH, first + WIDTH + 1, first + slots - 1);
        // Every live row: the selectors the kind's rule reads there.
        for r in s..=e {
            let (opening, within) = ((r - s) / span, (r - s) % span);
            let want = [
                slot_col(l, depth, span, count, opening, within),
                op_sel(span, count, opening, within),
                cp_col(l, depth, span, count, opening, within),
            ];
            let got = [
                per[slot][r] == Fp::ONE,
                per[op][r] == Fp::ONE,
                per[cp][r] == Fp::ONE,
            ];
            for (i, c) in [slot, op, cp].iter().enumerate() {
                assert!(
                    per[*c][r] == Fp::ZERO || per[*c][r] == Fp::ONE,
                    "row {r} column {c} is not a selector"
                );
                assert_eq!(
                    got[i], want[i],
                    "kind {k} at {s}, row {r}: selector {i} is not the Lean schedule's"
                );
            }
            if got[2] {
                checkpoints.push(r);
            }
            checked += 1;
        }
    }
    println!(
        "membership rows checked {checked}, checkpoints {}",
        checkpoints.len()
    );
    assert_eq!(members, LAUNCH_MEMBERS);
    assert_eq!(checkpoints, LAUNCH_CHECKPOINT_ROWS);
}
