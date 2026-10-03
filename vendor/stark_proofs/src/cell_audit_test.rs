// NONOS Operating System (AGPL-3.0-or-later)
//! Every cell at a region's edge that no constraint reads, classified.
//!
//! The overlay review changed one cell alone at each region's first row, last
//! live row and last row, every column, and found cells that neither layout
//! refused. A cell no constraint reads cannot move any value a constraint
//! checks, so it is sound to leave free, but only if that is why it is free.
//! This sorts each one:
//! - outside its region's columns: the region is narrower than the trace, and
//!   the columns past it belong to wider kinds on other rows;
//! - on a row no region reads: the row after a region's last live row, whose
//!   successor window belongs to nobody;
//! - inside a live region: named column by column, and each needs a reason.
//!
//! Measured: 1,014 unread of 2,156, all free by design.
//! The counts and the list of cells inside live regions are pinned, so a new
//! unread cell fails here until someone gives it a reason.
//!
//! `every_free_cell_in_the_trace_has_a_rule` does the same for all 360,448
//! cells of the trace, with a local check: a change at row r can only be seen
//! by the windows at r - 1 and r and by the boundaries on that cell. Every free
//! cell must fall under one named rule, and the counts are pinned to the
//! the contracts repository's coverage map of the same circuit.
//!
//! A cell the copy wiring binds is not free: `violations` checks the grand
//! product's transitions and closure, so moving a wired cell is refused. A cell
//! the permutation fixes cancels out of the product and is correctly free.

use crate::crypto::stark::air::{Air, ShieldRegion};
use crate::crypto::stark::field::Fp;
use crate::shield::key::Break;
use crate::shield::test::scenario::balanced_deployed;
use crate::witness_satisfies::{satisfies, violations};
use std::collections::BTreeMap;

#[test]
fn every_unread_edge_cell_is_classified() {
    let js = balanced_deployed(Break::None);
    let air = &js.wired;
    assert!(satisfies(air, &js.witness));
    let w = air.trace_width();
    let total = 1usize << air.log_trace_len();
    let per = air.periodic_columns();
    let map = air.wired().kind_map();
    let kinds = map.len();

    // Region instances as (first row, last live row, kind).
    let mut runs = Vec::new();
    for k in 0..kinds {
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
    let live_owner = |r: usize| {
        runs.iter()
            .find(|&&(s, e, _)| s <= r && r <= e)
            .map(|&(_, _, k)| k)
    };
    let mut edges: Vec<usize> = runs
        .iter()
        .flat_map(|&(s, e, _)| [s, e, e + 1])
        .filter(|&r| r < total)
        .collect();
    edges.sort_unstable();
    edges.dedup();

    let mut outside = BTreeMap::new();
    let mut no_region = BTreeMap::new();
    let mut inside = BTreeMap::new();
    let mut unread = 0usize;
    for &r in &edges {
        for c in 0..w {
            let mut t = js.witness.clone();
            t[r * w + c] = t[r * w + c] + Fp::ONE;
            if !violations(air, &t, 1).is_empty() {
                continue;
            }
            unread += 1;
            match live_owner(r) {
                Some(k) if c >= map[k].4 => *outside.entry(k).or_insert(0usize) += 1,
                Some(k) => {
                    let (s, e, _) = *runs
                        .iter()
                        .find(|&&(s, e, kk)| kk == k && s <= r && r <= e)
                        .unwrap();
                    let at = if r == s {
                        "first"
                    } else if r == e {
                        "last live"
                    } else {
                        "inner"
                    };
                    inside.entry((k, at, c)).or_insert_with(Vec::new).push(r);
                }
                None => *no_region.entry(c).or_insert(0usize) += 1,
            }
        }
    }
    let mut order: Vec<(usize, usize)> = runs.iter().map(|&(s, _, k)| (s, k)).collect();
    order.sort_unstable();
    for ((s, k), g) in order.iter().zip(air.regions()) {
        let name = match g {
            ShieldRegion::Balance(_) => "balance",
            ShieldRegion::Membership(_) => "membership",
            ShieldRegion::Index(_) => "index",
            ShieldRegion::Publics(_) => "publics",
            ShieldRegion::Live(_) => "live",
            ShieldRegion::Range(_) => "range",
            ShieldRegion::Count(_) => "count",
        };
        println!("kind {k} at {s}: {name}, width {}", map[*k].4);
    }
    println!(
        "edge rows {}, cells {}, unread {unread}",
        edges.len(),
        edges.len() * w
    );
    println!("outside the region's columns, by kind: {outside:?}");
    println!(
        "on rows no region reads: {} cells over {} columns",
        no_region.values().sum::<usize>(),
        no_region.len()
    );
    println!("inside a live region, (kind, row, column) -> rows:");
    for (key, rows) in &inside {
        println!("  {key:?} -> {rows:?}");
    }

    /*
     * Past a region's width nothing of that kind reads, and every other kind's
     * constraints are off on its rows. A region's last row is read only as the
     * successor of its last live row, which reads the state columns alone.
     */
    assert_eq!(outside.values().sum::<usize>(), 462);
    assert_eq!(no_region.values().sum::<usize>(), 528);
    /*
     * Inside a live region, each by name:
     * - balance column 5, the carry: read on the close row only;
     * - membership columns 29 to 33 of the depth-32 kinds, the bottom-direction
     *   pin: read on an opening's first row only;
     * - index column 1, the bit: past the last bit its weight is zero, so it
     *   only has to be a bit and moves no sum;
     * - publics column 0: rows past the public words have no boundary and no rule.
     */
    let mut expected: Vec<(usize, &str, usize)> =
        vec![(0, "first", 5), (3, "last live", 1), (6, "last live", 0)];
    for k in [2, 5] {
        for c in 29..34 {
            expected.push((k, "last live", c));
        }
    }
    expected.sort_unstable();
    let found: Vec<(usize, &str, usize)> = inside.keys().copied().collect();
    assert_eq!(
        found, expected,
        "an unread cell inside a live region has no reason yet"
    );
    assert_eq!(unread, 1014);
}

/// Why a cell no rule reads is free, or `None` when nothing explains it.
fn rule_for(
    owner: Option<(usize, usize, usize, &ShieldRegion)>,
    r: usize,
    c: usize,
    stack_w: usize,
    width: impl Fn(usize) -> usize,
) -> Option<&'static str> {
    let Some((s, e, k, g)) = owner else {
        return Some("a: padding row");
    };
    if c >= stack_w {
        return Some("a: mask column");
    }
    if c >= width(k) {
        return Some("a: past the region's width");
    }
    if r == e + 1 {
        return Some("b: region's last row");
    }
    let at = r - s;
    match g {
        ShieldRegion::Balance(b) if c == 5 && at != b.close_row() => {
            Some("b: carry off the close row")
        }
        ShieldRegion::Membership(m) => {
            let (l, depth, _) = m.schedule();
            let pin = m.dir0_col()..m.leaf_col() + 4;
            (pin.contains(&c) && at % ((depth + 1) * l) != 0)
                .then_some("b: pin off an opening's first row")
        }
        ShieldRegion::Index(i) if c == 1 && at >= i.value_row() => Some("b: bit past the last bit"),
        ShieldRegion::Publics(p) if c == 0 && at >= p.words.len() => {
            Some("b: row past the public words")
        }
        _ => None,
    }
}

/// What the full-trace audit found: the trace's size, the cells no window
/// and no boundary sees, each rule's count, and any free cell no rule names.
pub(crate) struct Audit {
    pub cells: usize,
    pub free: usize,
    pub by_rule: BTreeMap<&'static str, usize>,
    pub unexplained: Vec<(usize, usize)>,
}

impl Audit {
    /// Free cells under the rules of one class: `a` is outside every
    /// constraint by layout, `b` inside a region and free by name.
    pub fn class(&self, prefix: char) -> usize {
        self.by_rule
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(_, v)| v)
            .sum()
    }
}

/// Change every cell of a satisfying witness by one, alone, and record the
/// ones no window and no boundary sees, each sorted under the rule that says
/// why it is free. A change at row r is seen only by the windows at r - 1 and
/// r and by a boundary on that cell, so the check is local.
pub(crate) fn audit_free_cells(
    air: &crate::crypto::stark::air::WiredMultiGen,
    witness: &[Fp],
) -> Audit {
    let wm = air.wired();
    let (w, ws) = (air.trace_width(), air.window_size());
    let n = 1usize << air.log_trace_len();
    let per = air.periodic_columns();
    let map = wm.kind_map();
    let stack_w = w - wm.product_columns() - wm.mask_columns();

    // Region instances as (first row, last live row, kind), in row order.
    let mut runs = Vec::new();
    for k in 0..map.len() {
        let mut r = 0;
        while r < n {
            if per[k][r] == Fp::ONE {
                let s = r;
                while r < n && per[k][r] == Fp::ONE {
                    r += 1;
                }
                runs.push((s, r - 1, k));
            } else {
                r += 1;
            }
        }
    }
    runs.sort_unstable();
    let regions = air.regions();
    assert_eq!(runs.len(), regions.len());
    // A row's owner: the instance whose live rows or last row hold it.
    let owner = |r: usize| {
        runs.iter()
            .zip(regions)
            .find(|((s, e, _), _)| *s <= r && r <= *e + 1)
            .map(|(&(s, e, k), g)| (s, e, k, g))
    };

    let mut bnd: BTreeMap<(usize, usize), Fp> = BTreeMap::new();
    for (col, row, val) in air.boundary() {
        bnd.insert((row, col), val);
    }
    let holds = |t: &[Fp], r: usize| -> bool {
        if r + ws > n {
            return true;
        }
        let p: Vec<Fp> = per.iter().map(|c| c[r]).collect();
        air.transition(&t[r * w..(r + ws) * w], &p)
            .iter()
            .all(|v| *v == Fp::ZERO)
    };
    let free: Vec<Vec<usize>> = crate::crypto::stark::par::map_index(n, |r| {
        let mut t = witness.to_vec();
        let mut out = Vec::new();
        for c in 0..w {
            let old = t[r * w + c];
            t[r * w + c] = old + Fp::ONE;
            let seen = (r > 0 && !holds(&t, r - 1))
                || !holds(&t, r)
                || bnd.get(&(r, c)).is_some_and(|v| t[r * w + c] != *v);
            t[r * w + c] = old;
            if !seen {
                out.push(c);
            }
        }
        out
    });

    let mut by_rule: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut unexplained = Vec::new();
    for (r, cols) in free.iter().enumerate() {
        for &c in cols {
            match rule_for(owner(r), r, c, stack_w, |k| map[k].4) {
                Some(why) => *by_rule.entry(why).or_insert(0) += 1,
                None => unexplained.push((r, c)),
            }
        }
    }
    Audit {
        cells: n * w,
        free: free.iter().map(|c| c.len()).sum(),
        by_rule,
        unexplained,
    }
}

#[test]
fn every_free_cell_in_the_trace_has_a_rule() {
    let js = balanced_deployed(Break::None);
    let audit = audit_free_cells(&js.wired, &js.witness);
    let (a, b) = (audit.class('a'), audit.class('b'));
    println!(
        "cells {}, read {}, free {}: a {a}, b {b}",
        audit.cells,
        audit.cells - audit.free,
        audit.free
    );
    for (why, count) in &audit.by_rule {
        println!("  {why}: {count}");
    }
    assert!(
        audit.unexplained.is_empty(),
        "free cells no rule explains: {:?}",
        &audit.unexplained[..audit.unexplained.len().min(20)]
    );
    /*
     * Each word past the thirty sixth is one more pinned cell in the publics
     * region, taken from its rows past the public words.
     */
    let extra = crate::shield::join::publics::WORDS - 36;
    assert_eq!(audit.cells, 360_448);
    assert_eq!(audit.cells - audit.free, 219_011 + extra);
    assert_eq!(a, 119_980);
    assert_eq!(b, 21_457 - extra);
}
