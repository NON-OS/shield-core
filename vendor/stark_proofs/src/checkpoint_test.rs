// NONOS Operating System (AGPL-3.0-or-later)
//! The checkpoint rows of every membership region, held.
//!
//! A checkpoint is the row a region's last compression writes: its rate lanes
//! are the digest the path or chain reached, and a root or output pin reads
//! them. It used to be a slot injection, which read a witnessed direction and
//! sibling of a level that does not exist, bound only by the direction being a
//! bit. `checkpoint_fixed` gives the row its own selector: the successor holds
//! the compression's output in lanes 0 to 3 and zero in lanes 4 to 7, and the
//! direction and sibling cells are forced to zero.
//!
//! The rows come from the circuit's own selectors, per kind, so the test holds
//! whatever row the rule actually selects. Kinds 1, 2, 4 and 5 are the
//! membership kinds of the launch join-split, and the test pins that too.

use crate::crypto::stark::air::{Air, ShieldRegion};
use crate::crypto::stark::field::Fp;
use crate::shield::join::JoinSplit;
use crate::shield::key::Break;
use crate::shield::test::scenario::balanced_deployed;
use crate::witness_satisfies::{satisfies, violations};

const WIDTH: usize = 8;
const RATE: usize = 4;

/// The membership kinds, from the regions in stacking order matched to the
/// selector runs in row order.
fn membership_kinds(js: &JoinSplit) -> Vec<usize> {
    let cols = js.wired.periodic_columns();
    let kinds = js.wired.wired().kind_map().len();
    let mut runs = Vec::new();
    for k in 0..kinds {
        let mut r = 0;
        while r < cols[k].len() {
            if cols[k][r] == Fp::ONE {
                runs.push((r, k));
                while r < cols[k].len() && cols[k][r] == Fp::ONE {
                    r += 1;
                }
            } else {
                r += 1;
            }
        }
    }
    runs.sort();
    assert_eq!(
        runs.len(),
        js.wired.regions().len(),
        "one selector run per region"
    );
    let mut out: Vec<usize> = runs
        .iter()
        .zip(js.wired.regions())
        .filter(|(_, g)| matches!(g, ShieldRegion::Membership(_)))
        .map(|((_, k), _)| *k)
        .collect();
    out.dedup();
    out
}

/// Every row a membership kind's rule treats as its checkpoint. The fixed
/// circuit selects it with the kind's last periodic slot. The launch circuit
/// has no such slot: there the checkpoint is the slot boundary whose successor
/// the honest walk leaves with an empty capacity.
fn checkpoint_rows(js: &JoinSplit) -> Vec<(usize, usize)> {
    let cols = js.wired.periodic_columns();
    let map = js.wired.wired().kind_map();
    let w = js.wired.trace_width();
    let mut out = Vec::new();
    for k in membership_kinds(js) {
        let (first, slots, ..) = map[k];
        for r in 0..cols[k].len() - 1 {
            if cols[k][r] != Fp::ONE {
                continue;
            }
            let hit = if cfg!(feature = "launch_v1") {
                cols[first + WIDTH][r] == Fp::ONE
                    && (RATE..WIDTH).all(|j| js.witness[(r + 1) * w + j] == Fp::ZERO)
            } else {
                cols[first + slots - 1][r] == Fp::ONE
            };
            if hit {
                out.push((k, r));
            }
        }
    }
    out
}

/// Re-fill a region from `from` to its last live row so every transition holds
/// again after a cell was changed: the squares from each row's state, then the
/// next row's state from the transition's residual.
fn refill(air: &impl Air, wit: &mut [Fp], per: &[Vec<Fp>], from: usize, last_live: usize) {
    let w = air.trace_width();
    let sq = WIDTH + 1 + RATE;
    for r in from..=last_live + 1 {
        for j in 0..WIDTH {
            let x2 = wit[r * w + j] * wit[r * w + j];
            wit[r * w + sq + j] = x2;
            wit[r * w + sq + WIDTH + j] = x2 * x2;
        }
        if r > last_live {
            break;
        }
        let window: Vec<Fp> = wit[r * w..(r + 2) * w].to_vec();
        let p: Vec<Fp> = per.iter().map(|c| c[r]).collect();
        let out = air.transition(&window, &p);
        for j in 0..WIDTH {
            wit[(r + 1) * w + j] = wit[(r + 1) * w + j] - out[j];
        }
    }
}

#[test]
fn the_honest_witness_satisfies() {
    let js = balanced_deployed(Break::None);
    assert!(satisfies(&js.wired, &js.witness));
}

#[test]
fn the_membership_kinds_are_one_two_four_and_five() {
    let js = balanced_deployed(Break::None);
    assert_eq!(membership_kinds(&js), vec![1, 2, 4, 5]);
    let rows = checkpoint_rows(&js);
    for k in [1, 2, 4, 5] {
        assert!(
            rows.iter().any(|&(j, _)| j == k),
            "no checkpoint row found for kind {k}"
        );
    }
    assert_eq!(rows.len(), 20);
}

/// Every cell the per-row rules read, on the row that writes a checkpoint and
/// on the checkpoint row itself, changed alone: state, direction, sibling and
/// the split squares. The columns past them are the bottom-direction pin, read
/// on an opening's first row only, and the overlay width of other kinds. The
/// fixed rule refuses every change; the launch rule leaves the checkpoint row's
/// direction and sibling unread.
#[test]
fn every_checkpoint_cell_changed_alone_is_refused() {
    let js = balanced_deployed(Break::None);
    let w = js.wired.trace_width();
    let per_row = (WIDTH + 1 + RATE + 2 * WIDTH).min(w);
    let mut free = Vec::new();
    let mut checked = 0usize;
    for (k, r) in checkpoint_rows(&js) {
        for row in [r, r + 1] {
            for c in 0..per_row {
                let mut t = js.witness.clone();
                t[row * w + c] = if c == WIDTH {
                    Fp::ONE - t[row * w + c]
                } else {
                    t[row * w + c] + Fp::ONE
                };
                if violations(&js.wired, &t, 1).is_empty() {
                    free.push((k, row, c));
                }
                checked += 1;
            }
        }
    }
    println!(
        "checkpoint cells checked {checked}, left free {}",
        free.len()
    );
    #[cfg(not(feature = "launch_v1"))]
    assert!(free.is_empty(), "checkpoint cells left free: {free:?}");
    #[cfg(feature = "launch_v1")]
    assert!(
        !free.is_empty(),
        "the launch rule should leave the checkpoint direction unread"
    );
}

/// A checkpoint that shows a digest its walk never reached, on every
/// checkpoint. Where a sibling lies below it in the same opening, that sibling
/// is changed so the walk reaches a wrong digest and the checkpoint is made to
/// show the true one: a wrong path under the true root. Where the opening is a
/// single compression, the checkpoint is made to show a chosen digest, which
/// the output binding on the next row refuses in both circuits. Either way the
/// injection row is given direction one and the digest to show as its sibling,
/// and the region is re-filled so every other transition holds. The launch
/// rule accepts every wrong path; the fixed rule refuses everything.
#[test]
fn a_checkpoint_showing_an_unwalked_digest_is_refused() {
    let js = balanced_deployed(Break::None);
    let air = &js.wired;
    let per = air.periodic_columns();
    let map = air.wired().kind_map();
    let w = air.trace_width();
    let rows = checkpoint_rows(&js);
    let mut accepted = Vec::new();
    let mut below = 0usize;
    for &(k, r) in &rows {
        let (first, ..) = map[k];
        let slot = first + WIDTH;
        let mut last_live = r;
        while per[k][last_live + 1] == Fp::ONE {
            last_live += 1;
        }
        // The nearest injection below the checkpoint, inside the same opening.
        let op = first + WIDTH + 1;
        let mut s = r;
        let srow = loop {
            if s == 0 || per[k][s - 1] != Fp::ONE || per[op][s - 1] == Fp::ONE {
                break None;
            }
            s -= 1;
            if per[slot][s] == Fp::ONE {
                break Some(s);
            }
        };
        let mut t = js.witness.clone();
        let digest: Vec<Fp> = t[(r + 1) * w..(r + 1) * w + RATE].to_vec();
        let shown: Vec<Fp> = match srow {
            Some(srow) => {
                below += 1;
                t[srow * w + WIDTH + 1] = t[srow * w + WIDTH + 1] + Fp::ONE;
                refill(air, &mut t, &per, srow, last_live);
                assert_ne!(
                    t[(r + 1) * w..(r + 1) * w + RATE],
                    digest[..],
                    "the wrong sibling moved nothing"
                );
                digest
            }
            None => digest.iter().map(|d| *d + Fp::ONE).collect(),
        };
        t[r * w + WIDTH] = Fp::ONE;
        for c in 0..RATE {
            t[r * w + WIDTH + 1 + c] = shown[c];
        }
        refill(air, &mut t, &per, r, last_live);
        #[cfg(feature = "launch_v1")]
        assert_eq!(t[(r + 1) * w..(r + 1) * w + RATE], shown[..]);
        if violations(air, &t, 1).is_empty() {
            accepted.push((k, r));
        }
    }
    println!(
        "checkpoints tried {} ({below} with a wrong path below), accepted {}",
        rows.len(),
        accepted.len()
    );
    #[cfg(not(feature = "launch_v1"))]
    assert!(
        accepted.is_empty(),
        "unwalked digests accepted at {accepted:?}"
    );
    #[cfg(feature = "launch_v1")]
    assert_eq!(
        accepted.len(),
        below,
        "the launch rule accepts every wrong path"
    );
    assert!(below >= 4, "too few checkpoints have a sibling below them");
}
