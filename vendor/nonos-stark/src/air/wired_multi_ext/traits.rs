// NONOS Operating System (AGPL-3.0-or-later)
//! The Air and AirExt impls of the multi-group wired engine: the region
//! transitions fused, then one product lane per group.

use super::WiredMultiExt;
use crate::air::spec::{Air, AirExt};
use crate::air::{chained_product, fusion};
use crate::field::{Fp, Fp2};
use alloc::vec::Vec;

impl AirExt for WiredMultiExt {
    fn transition_ext(&self, window: &[Fp2], periodic: &[Fp2]) -> Vec<Fp2> {
        let mut out = fusion::combine(
            &self.stack,
            &self.regions,
            self.num_transition(),
            self.stride(),
            window,
            periodic,
            |i, l, p| self.regions[i].transition_ext(l, p),
        );
        self.append_groups(&mut out, window, periodic, &[]);
        out
    }

    fn challenge_lanes(&self) -> usize {
        if self.ext_challenges() {
            2
        } else {
            1
        }
    }

    fn mask_pair(&self) -> Option<(usize, usize)> {
        let w = self.trace_width();
        (self.ext_challenges() && self.mask_columns() == 2).then_some((w - 2, w - 1))
    }
}

impl Air for WiredMultiExt {
    fn log_trace_len(&self) -> u32 {
        self.stack.log_trace_len()
    }

    fn trace_width(&self) -> usize {
        self.stride()
    }

    fn window_size(&self) -> usize {
        self.stack.window
    }

    fn constraint_degree(&self) -> usize {
        let mut d = 1usize;
        for region in &self.regions {
            d = d.max(region.constraint_degree());
        }
        /*
         * A lane costs its factors plus the selector, so width plus two. The
         * chained form caps the width at BLOCK however wide the permutation
         * gets, which is why the groups could go.
         */
        let lane_width = if self.chained {
            core::cmp::min(chained_product::BLOCK, self.groups[0].wired_cols.len())
        } else {
            self.groups
                .iter()
                .map(|g| g.wired_cols.len())
                .max()
                .unwrap_or(0)
        };
        (d + 2).max(lane_width + 2)
    }

    fn num_transition(&self) -> usize {
        self.region_transitions + self.product_columns()
    }

    fn periodic_columns(&self) -> Vec<Vec<Fp>> {
        let total = 1usize << self.log_trace_len();
        let span = self.closes_at();
        let mut cols = fusion::base_periodic(&self.stack, &self.regions, total);
        let mut gp_sel = alloc::vec![Fp::ZERO; total];
        for item in gp_sel.iter_mut().take(span) {
            *item = Fp::ONE;
        }
        cols.push(gp_sel);
        let mut row = alloc::vec![Fp::ZERO; total];
        for (r, slot) in row.iter_mut().enumerate().take(span) {
            *slot = Fp::from_u64(r as u64);
        }
        cols.push(row);
        for group in &self.groups {
            let k = group.wired_cols.len();
            for j in 0..k {
                let mut sig = alloc::vec![Fp::ZERO; total];
                for (r, slot) in sig.iter_mut().enumerate().take(span) {
                    *slot = Fp::from_u64(group.sigma[r * k + j] as u64);
                }
                cols.push(sig);
            }
        }
        cols
    }

    fn transition(&self, window: &[Fp], periodic: &[Fp]) -> Vec<Fp> {
        let mut out = fusion::combine(
            &self.stack,
            &self.regions,
            self.num_transition(),
            self.stride(),
            window,
            periodic,
            |i, l, p| self.regions[i].transition(l, p),
        );
        self.append_groups(&mut out, window, periodic, &[]);
        out
    }

    fn boundary(&self) -> Vec<(usize, usize, Fp)> {
        let mut b = fusion::base_boundary(&self.stack, &self.regions);
        b.extend(self.extra_boundary.iter().copied());
        let span = self.closes_at();
        /*
         * A boundary only says something about a column that crosses rows.
         * Every packed product column does; of the chained ones only the last.
         * The partials are computed by their own lanes from that row's cells,
         * so pinning them would pin a result rather than a claim.
         */
        let pinned = if self.chained {
            self.product_columns() - 1..self.product_columns()
        } else {
            0..self.groups.len()
        };
        if self.ext {
            // Each product is `c0 + c1 X`, and one is `(1, 0)`.
            for g in 0..self.groups.len() {
                let at = self.stack.width + 2 * g;
                for row in [0, span] {
                    b.push((at, row, Fp::ONE));
                    b.push((at + 1, row, Fp::ZERO));
                }
            }
            return b;
        }
        for g in pinned {
            b.push((self.stack.width + g, 0, Fp::ONE));
            b.push((self.stack.width + g, span, Fp::ONE));
        }
        b
    }
}
