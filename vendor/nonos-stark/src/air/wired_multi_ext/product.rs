// NONOS Operating System (AGPL-3.0-or-later)

//! Each group's grand product, and the whole transition over any field.
//!
//! This is the half of the engine a recursive verifier replays: the region
//! bodies come from the caller's closure, and everything the permutation
//! argument itself contributes is here.

use super::super::super::field::{Felt, Fp};
use super::super::chained_product;
use super::super::fusion;
use super::super::spec::Air;
use super::pair::Pair;
use super::{GpGroup, WiredMultiExt};
use alloc::vec::Vec;

impl WiredMultiExt {
    /// The supplied pair when a caller has one, the circuit's otherwise. A
    /// recursive verifier supplies witness cells bound to its own transcript.
    fn challenge_pair<F: Felt>(&self, group: &GpGroup, supplied: &[F]) -> (F, F) {
        if supplied.len() >= 2 {
            (supplied[0], supplied[1])
        } else {
            (F::from_base(group.beta), F::from_base(group.gamma))
        }
    }

    /// Beta and gamma as pairs: the supplied four, beta's components then
    /// gamma's, when a caller has them, the circuit's otherwise.
    fn challenge_pairs<F: Felt>(&self, group: &GpGroup, supplied: &[F]) -> (Pair<F>, Pair<F>) {
        if supplied.len() >= 4 {
            (Pair(supplied[0], supplied[1]), Pair(supplied[2], supplied[3]))
        } else {
            (
                Pair(F::from_base(group.beta), F::from_base(self.beta_x)),
                Pair(F::from_base(group.gamma), F::from_base(self.gamma_x)),
            )
        }
    }

    /// The group's grand product at `Fp2` challenges, as its two components.
    /// The running product is columns `2g` and `2g + 1` above the regions.
    fn group_product_ext<F: Felt>(
        &self,
        g: usize,
        group: &GpGroup,
        window: &[F],
        periodic: &[F],
        chal: &[F],
    ) -> [F; 2] {
        let (b, gm) = self.challenge_pairs(group, chal);
        let stride = self.stride();
        let at = self.stack.width + 2 * g;
        let z = Pair(window[at], window[at + 1]);
        let z_next = Pair(window[stride + at], window[stride + at + 1]);
        let sgb = self.sig_base[g];
        let kf = F::from_base(Fp::from_u64(group.wired_cols.len() as u64));
        let row = periodic[self.row_idx];
        let mut num = Pair::one();
        let mut den = Pair::one();
        for (j, &col) in group.wired_cols.iter().enumerate() {
            let v = Pair(window[col], F::ZERO);
            let id = row * kf + F::from_base(Fp::from_u64(j as u64));
            let sig = periodic[sgb + j];
            num = num.mul(v.add(b.scale(id)).add(gm));
            den = den.mul(v.add(b.scale(sig)).add(gm));
        }
        let sel = periodic[self.sel_idx];
        let product = z_next.mul(den).sub(z.mul(num));
        let carry = z_next.sub(z);
        [
            sel * product.0 + (F::ONE - sel) * carry.0,
            sel * product.1 + (F::ONE - sel) * carry.1,
        ]
    }

    fn group_product<F: Felt>(
        &self,
        g: usize,
        group: &GpGroup,
        window: &[F],
        periodic: &[F],
        chal: &[F],
    ) -> F {
        let (b, gm) = self.challenge_pair(group, chal);
        let stride = self.stride();
        let width = self.stack.width;
        let z = window[width + g];
        let z_next = window[stride + width + g];
        let sgb = self.sig_base[g];
        let kf = F::from_base(Fp::from_u64(group.wired_cols.len() as u64));
        let row = periodic[self.row_idx];
        let mut num = F::ONE;
        let mut den = F::ONE;
        for (j, &col) in group.wired_cols.iter().enumerate() {
            let v = window[col];
            let id = row * kf + F::from_base(Fp::from_u64(j as u64));
            let sig = periodic[sgb + j];
            num = num * (v + b * id + gm);
            den = den * (v + b * sig + gm);
        }
        let gp_sel = periodic[self.sel_idx];
        let product = z_next * den - z * num;
        let carry = z_next - z;
        gp_sel * product + (F::ONE - gp_sel) * carry
    }

    /// The full transition over any field, with the caller supplying each
    /// region's constraint evaluation. This is how a recursive verifier
    /// recomputes the whole wired AIR inside its own circuit: the layout,
    /// selectors and grand products replay here, and the closure dispatches to
    /// each region's own generic transition, which the boxed form cannot carry.
    pub fn transition_generic<F: Felt>(
        &self,
        window: &[F],
        periodic: &[F],
        region: impl Fn(usize, &[F], &[F]) -> Vec<F>,
    ) -> Vec<F> {
        self.transition_generic_at(window, periodic, &[], region)
    }

    /// The same, at challenges the caller supplies rather than the ones this
    /// AIR carries. Pass beta then gamma, or nothing to use the circuit's.
    pub fn transition_generic_at<F: Felt>(
        &self,
        window: &[F],
        periodic: &[F],
        chal: &[F],
        region: impl Fn(usize, &[F], &[F]) -> Vec<F>,
    ) -> Vec<F> {
        let mut out = fusion::combine(
            &self.stack,
            &self.regions,
            self.num_transition(),
            self.stride(),
            window,
            periodic,
            region,
        );
        self.append_groups(&mut out, window, periodic, chal);
        out
    }

    pub(super) fn append_groups<F: Felt>(
        &self,
        out: &mut [F],
        window: &[F],
        periodic: &[F],
        chal: &[F],
    ) {
        if self.chained {
            for (m, lane) in self
                .chained_lanes(window, periodic, chal)
                .into_iter()
                .enumerate()
            {
                out[self.region_transitions + m] = lane;
            }
            return;
        }
        if self.ext {
            for (g, group) in self.groups.iter().enumerate() {
                let [c0, c1] = self.group_product_ext(g, group, window, periodic, chal);
                out[self.region_transitions + 2 * g] = c0;
                out[self.region_transitions + 2 * g + 1] = c1;
            }
            return;
        }
        for (g, group) in self.groups.iter().enumerate() {
            out[self.region_transitions + g] = self.group_product(g, group, window, periodic, chal);
        }
    }

    /// The chained lanes at one window. Slots are numbered `row * k + j` over
    /// the whole permutation rather than per block, so the row column serves
    /// every block just as it serves every group.
    fn chained_lanes<F: Felt>(&self, window: &[F], periodic: &[F], chal: &[F]) -> Vec<F> {
        let group = &self.groups[0];
        let (beta, gamma) = self.challenge_pair(group, chal);
        let k = group.wired_cols.len();
        let blocks = chained_product::blocks(k);
        let stride = self.stride();
        let width = self.stack.width;
        let sgb = self.sig_base[0];
        let kf = F::from_base(Fp::from_u64(k as u64));
        let row = periodic[self.row_idx];

        let mut steps = Vec::with_capacity(blocks);
        for m in 0..blocks {
            let lo = m * chained_product::BLOCK;
            let hi = core::cmp::min(lo + chained_product::BLOCK, k);
            let values: Vec<F> = (lo..hi).map(|j| window[group.wired_cols[j]]).collect();
            let identity: Vec<F> = (lo..hi)
                .map(|j| row * kf + F::from_base(Fp::from_u64(j as u64)))
                .collect();
            let sigma: Vec<F> = (lo..hi).map(|j| periodic[sgb + j]).collect();
            steps.push(chained_product::step_at(
                &values, &identity, &sigma, beta, gamma,
            ));
        }

        let acc: Vec<F> = (0..blocks).map(|m| window[width + m]).collect();
        let acc_next: Vec<F> = (0..blocks).map(|m| window[stride + width + m]).collect();
        chained_product::lanes(&steps, &acc, &acc_next, periodic[self.sel_idx])
    }
}
