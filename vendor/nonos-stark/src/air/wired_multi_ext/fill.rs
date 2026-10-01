// NONOS Operating System (AGPL-3.0-or-later)

//! Placing a witness into the stacked trace and filling the running products
//! over it. The layout is `fusion`'s; what is here is the argument's own
//! columns, which no region owns.

use super::super::super::field::{Fp, Fp2};
use super::super::chained_product;
use super::super::fusion;
use super::super::spec::Air;
use super::{GpGroup, WiredMultiExt};
use alloc::vec::Vec;

impl WiredMultiExt {
    fn ratio(&self, group: &GpGroup, row: &[Fp], r: usize) -> Fp {
        let k = group.wired_cols.len();
        let (b, gm) = (group.beta, group.gamma);
        let mut num = Fp::ONE;
        let mut den = Fp::ONE;
        for (j, &col) in group.wired_cols.iter().enumerate() {
            let v = row[col];
            let id = r * k + j;
            num = num * (v + b * Fp::from_u64(id as u64) + gm);
            den = den * (v + b * Fp::from_u64(group.sigma[id] as u64) + gm);
        }
        num * den.inv()
    }

    /// `ratio` at the `Fp2` challenges.
    fn ratio_ext(&self, group: &GpGroup, row: &[Fp], r: usize) -> Fp2 {
        let k = group.wired_cols.len();
        let (b, gm) = self.challenges_ext();
        let mut num = Fp2::ONE;
        let mut den = Fp2::ONE;
        for (j, &col) in group.wired_cols.iter().enumerate() {
            let v = Fp2::from_base(row[col]);
            let id = r * k + j;
            num = num * (v + b * Fp2::from_base(Fp::from_u64(id as u64)) + gm);
            den = den * (v + b * Fp2::from_base(Fp::from_u64(group.sigma[id] as u64)) + gm);
        }
        num * den.inv()
    }

    /// The packed running products at `Fp2` challenges, two columns each.
    fn fill_ext(&self, trace: &mut [Fp], stride: usize, total: usize, span: usize) {
        for (g, group) in self.groups.iter().enumerate() {
            let at = self.stack.width + 2 * g;
            let mut z = Fp2::ONE;
            for r in 0..total {
                trace[r * stride + at] = z.c0;
                trace[r * stride + at + 1] = z.c1;
                if r < span {
                    let base = r * stride;
                    z = z * self.ratio_ext(group, &trace[base..base + stride], r);
                }
            }
        }
    }

    /// The witness: regions in the low columns, each group's running product in one
    /// column above them.
    pub fn trace(&self, traces: &[Vec<Fp>]) -> Vec<Fp> {
        let stride = self.stride();
        let total = 1usize << self.log_trace_len();
        let mut trace = fusion::place_traces(&self.stack, &self.regions, stride, total, traces);
        let span = self.closes_at();
        if self.chained {
            self.fill_chained(&mut trace, stride, total, span);
            return trace;
        }
        if self.ext {
            self.fill_ext(&mut trace, stride, total, span);
            return trace;
        }
        for (g, group) in self.groups.iter().enumerate() {
            let z_col = self.stack.width + g;
            let mut z = Fp::ONE;
            for r in 0..total {
                trace[r * stride + z_col] = z;
                if r < span {
                    let base = r * stride;
                    z = z * self.ratio(group, &trace[base..base + stride], r);
                }
            }
        }
        trace
    }

    /// The accumulator columns of the chained argument. The last is the
    /// running product, which the boundary pins and the previous row hands on;
    /// the rest are this row's partials, so no lane sees more than `BLOCK`
    /// factors. Off the argument's rows the product holds and the partials are
    /// left where they lie, which nothing reads.
    fn fill_chained(&self, trace: &mut [Fp], stride: usize, total: usize, span: usize) {
        let group = &self.groups[0];
        let k = group.wired_cols.len();
        let blocks = chained_product::blocks(k);
        let (b, gm) = (group.beta, group.gamma);
        let zcol = self.stack.width + blocks - 1;
        let mut z = Fp::ONE;
        for r in 0..total {
            trace[r * stride + zcol] = z;
            if r >= span {
                continue;
            }
            let base = r * stride;
            let mut running = z;
            for m in 0..blocks {
                let lo = m * chained_product::BLOCK;
                let hi = core::cmp::min(lo + chained_product::BLOCK, k);
                let mut num = Fp::ONE;
                let mut den = Fp::ONE;
                for j in lo..hi {
                    let v = trace[base + group.wired_cols[j]];
                    let id = r * k + j;
                    num = num * (v + b * Fp::from_u64(id as u64) + gm);
                    den = den * (v + b * Fp::from_u64(group.sigma[id] as u64) + gm);
                }
                running = running * num * den.inv();
                if m + 1 < blocks {
                    trace[base + self.stack.width + m] = running;
                }
            }
            z = running;
        }
    }

    /// Recompute the running products over a witness whose cells have moved,
    /// leaving the regions' columns alone. What a prover does once it has
    /// decided what its trace says.
    pub fn refill_products(&self, trace: &mut [Fp]) {
        let stride = self.stride();
        let total = trace.len() / stride;
        let span = self.closes_at();
        if self.chained {
            self.fill_chained(trace, stride, total, span);
            return;
        }
        if self.ext {
            self.fill_ext(trace, stride, total, span);
            return;
        }
        for (g, group) in self.groups.iter().enumerate() {
            let z_col = self.stack.width + g;
            let mut z = Fp::ONE;
            for r in 0..total {
                trace[r * stride + z_col] = z;
                if r < span {
                    let base = r * stride;
                    z = z * self.ratio(group, &trace[base..base + stride], r);
                }
            }
        }
    }
}
