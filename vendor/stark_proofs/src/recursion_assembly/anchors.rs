// NONOS Operating System (AGPL-3.0-or-later)
//! The constants the chain openings anchor to, as pins and classes.
//!
//! The chain openings anchor to constants no region pins in witness form: the
//! zero leaf that starts every chain, and for the sidecar the baked periodic
//! root every chain must reach. The trace chain's root is the proof's, bound
//! to the transcript's absorb cells by the roots family, so only its zero leaf
//! anchors here.
//!
//! Two ways to say it, and which one is a parameter rather than a setting,
//! because an artifact has to say what it is. Per cell: one boundary for each
//! of the 512 anchored cells, which is what every verifier deployed so far
//! reads. Collapsed: one pin per distinct value and one wiring class over
//! every cell that shares it, five pins where there were 512. A class forces
//! equality and the pin forces the value, so together they say what the 512
//! said over the same cells; each inner boundary costs a wrap ten DEEP terms
//! and two slots of width, and the wrap's compose region read off the real
//! outer falls from 9,372 base columns to 7,344. The cells sit in columns the
//! chains already wire, so the classes add no sigma column.
//!
//! The boundary count is a transcript position in the on-chain verifier, so
//! moving it needs a re-emit and a fresh verifier. `DEPLOYED` is per cell
//! until the first settled spend has landed on the verifier that exists, and
//! is flipped in one place after it.

use super::groups;
use super::layout::Layout;
use super::parts::Parts;
use crate::crypto::stark::air::{AirExt, GenericTransition, RATE};
use crate::crypto::stark::field::Fp;
use alloc::vec::Vec;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Anchors {
    /// One boundary per anchored cell. What the deployed verifier reads.
    PerCell,
    /// One pin per distinct value, a class over the rest.
    Collapsed,
}

/// The form every emitter and gate uses unless it says otherwise.
pub const DEPLOYED: Anchors = Anchors::PerCell;

impl Anchors {
    pub fn name(self) -> &'static str {
        match self {
            Anchors::PerCell => "per_cell",
            Anchors::Collapsed => "collapsed",
        }
    }
}

/// One wiring class over cells that must all equal one anchored constant, as
/// a binding the packer and the single permutation both take. The cells are
/// chained into a cycle; the first is the one the boundary pins.
///
/// A bind's swaps name lanes into `wired_cols`, not columns. The first
/// version of this stored columns and the packer indexed a one-lane bind at
/// lane four, which is the kind of mistake that is a panic here and would be
/// a silently wrong permutation anywhere the index happened to be in range.
fn anchor_class(label: &'static str, cells: &[(usize, usize)]) -> groups::Bind {
    let mut wired_cols: Vec<usize> = cells.iter().map(|c| c.1).collect();
    wired_cols.sort_unstable();
    wired_cols.dedup();
    let lane = |c: usize| wired_cols.iter().position(|&x| x == c).expect("a cell's own column");
    let swaps: Vec<(usize, usize, usize, usize)> = cells
        .windows(2)
        .map(|w| (w[0].0, lane(w[0].1), w[1].0, lane(w[1].1)))
        .collect();
    groups::Bind { wired_cols, swaps, label }
}

/// The pins, as `(column, row, value)`, and under `Collapsed` the classes that
/// carry each to every other cell holding the same constant.
pub(super) fn anchor_pins<A: AirExt + GenericTransition + 'static>(
    parts: &[Parts<A>],
    lays: &[Layout],
    n_q: usize,
    with_rounds: bool,
    mode: Anchors,
) -> (Vec<(usize, usize, Fp)>, Vec<groups::Bind>) {
    let mut zero_cells: Vec<(usize, usize)> = Vec::new();
    let mut root_cells: [Vec<(usize, usize)>; RATE] = core::array::from_fn(|_| Vec::new());
    let mut root_value: Option<[Fp; RATE]> = None;
    for (p, lay) in parts.iter().zip(lays.iter()) {
        for q in 0..n_q {
            for j in 0..RATE {
                zero_cells.push((lay.ta_off[q], j));
                if with_rounds {
                    zero_cells.push((lay.ra_off[q], j));
                }
            }
        }
        if let Some(root) = p.sidecar_root {
            assert!(
                root_value.is_none_or(|r| r == root),
                "aggregated inners must share one baked periodic root"
            );
            root_value = Some(root);
            for q in 0..n_q {
                let pa = lay.pa_off[q];
                for (j, cells) in root_cells.iter_mut().enumerate() {
                    zero_cells.push((pa, j));
                    cells.push((pa + lay.pa_depth * lay.l, j));
                }
            }
        }
    }
    let mut pins = Vec::new();
    let mut binds = Vec::new();
    match mode {
        /*
         * In the order the boundaries have always been emitted, walked again
         * rather than read off the collected lists, because that order is the
         * order the composition assigns its boundary coefficients in. The
         * same 820 pins in another order are a different composition, and a
         * verifier generated from the deployed boundary file would refuse a
         * proof made against them. The per-cell emit is held to the deployed
         * directory's digests, which is what caught the first version of this
         * branch emitting the right pins in the wrong order.
         */
        Anchors::PerCell => {
            for (p, lay) in parts.iter().zip(lays.iter()) {
                for q in 0..n_q {
                    for j in 0..RATE {
                        pins.push((j, lay.ta_off[q], Fp::ZERO));
                    }
                    if with_rounds {
                        for j in 0..RATE {
                            pins.push((j, lay.ra_off[q], Fp::ZERO));
                        }
                    }
                }
                if let Some(root) = p.sidecar_root {
                    for q in 0..n_q {
                        let pa = lay.pa_off[q];
                        for (j, lane) in root.iter().enumerate() {
                            pins.push((j, pa, Fp::ZERO));
                            pins.push((j, pa + lay.pa_depth * lay.l, *lane));
                        }
                    }
                }
            }
        }
        Anchors::Collapsed => {
            if let Some(&(row, col)) = zero_cells.first() {
                pins.push((col, row, Fp::ZERO));
                binds.push(anchor_class("anchor_zero", &zero_cells));
            }
            if let Some(root) = root_value {
                for (j, cells) in root_cells.iter().enumerate() {
                    if let Some(&(row, col)) = cells.first() {
                        pins.push((col, row, root[j]));
                        binds.push(anchor_class("anchor_root", cells));
                    }
                }
            }
        }
    }
    (pins, binds)
}

/// Append one pin per public word, inner by inner in the order the outer's
/// publics list them, on the cell the transcript absorbed it from. The values
/// are the calldata words: a verifier reads pin k from public word k, never
/// from the circuit. The strip form binds no slot and adds none. Returns the
/// count, which `WiredMultiExt::mark_public_pins` takes.
pub(super) fn public_pins<A: AirExt + GenericTransition + 'static>(
    parts: &[Parts<A>],
    lays: &[Layout],
    pins: &mut Vec<(usize, usize, Fp)>,
) -> usize {
    let mut n = 0;
    for (p, lay) in parts.iter().zip(lays.iter()) {
        for k in 0..lay.n_pub {
            let (row, col) = groups::absorbed(lay, 0, lay.cells.publics[k]);
            pins.push((col, row, p.publics[k]));
        }
        n += lay.n_pub;
    }
    n
}
