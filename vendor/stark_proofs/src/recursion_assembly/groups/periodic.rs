// NONOS Operating System (AGPL-3.0-or-later)
//! The periodic bindings. Plain path: each recomputed P_j(z), on its run's
//! last row, is the compose input cell that consumes it. Sidecar path: the
//! recompute region does not exist; the claim absorbed in the transcript is
//! the compose input and every query's deep quotient claim, one three-way tie
//! per column, and the opened rows those quotients divide are bound to the
//! authenticated chunks elsewhere.

use super::super::layout::Layout;
use super::bind::Bind;
use super::bind::{chain, group_auto, labeled};
use super::roots::absorbed;
use alloc::vec::Vec;

pub fn periodic(lay: &Layout, out: &mut Vec<Bind>) {
    if lay.sidecar {
        let base = lay.width_inner * lay.window_inner + 1;
        for j in 0..lay.n_pz {
            let (pc0, pc1) = (lay.c_periodic_col + 2 * j, lay.c_periodic_col + 2 * j + 1);
            for lane in 0..2 {
                let claim = absorbed(lay, 0, lay.cells.claims[2 * j + lane]);
                let cc = if lane == 0 { pc0 } else { pc1 };
                let mut cells: Vec<(usize, usize)> = alloc::vec![claim, lay.ccell(cc)];
                for q in 0..lay.n_q {
                    cells.push((lay.d_off[q] + base + j, 8 + lane));
                }
                let mut sw = Vec::new();
                chain(&cells, &mut sw);
                let mut wcols: Vec<usize> = cells.iter().map(|c| c.1).collect();
                wcols.sort_unstable();
                wcols.dedup();
                out.push(labeled("claim", lay.span, wcols, &sw));
            }
        }
        return;
    }
    for j in 0..lay.n_pz {
        let r = lay.pz_off + (j + 1) * lay.t_inner - 1;
        let (pc0, pc1) = (lay.c_periodic_col + 2 * j, lay.c_periodic_col + 2 * j + 1);
        let (r0, c0) = lay.ccell(pc0);
        let (r1, c1) = lay.ccell(pc1);
        out.push(group_auto(lay.span, &[(r, 10, r0, c0), (r, 11, r1, c1)]));
    }
}
