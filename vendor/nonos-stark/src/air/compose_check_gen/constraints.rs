// NONOS Operating System (AGPL-3.0-or-later)

//! The compose gadget's constraints over any field: the vanishing tower, the
//! factor E, the recompute or its strip pins, the boundary quotients, and the
//! batched sum against the claimed composition. This is where an arbitrary
//! inner AIR is arithmetized, by evaluating its own constraint code at
//! `Ext2<F>` rather than transcribing it.

use super::super::super::field::{Ext2, Felt, Fp};
use super::super::spec::AirExt;
use super::gadget::ComposeCheckGen;
use super::generic::GenericTransition;
use alloc::vec::Vec;

impl<A: AirExt + GenericTransition> ComposeCheckGen<A> {
    /// The transition over any field, for in-circuit recomputation one layer up.
    ///
    /// This is the region that recomputes its own inner's arithmetic, so
    /// exposing it is what allows a recursion to be built over a circuit which
    /// already contains one. It forwards to the definition `transition` and
    /// `transition_ext` both use, so a layer above and the prover below cannot
    /// end up checking different constraints.
    pub fn transition_gen<F: Felt>(&self, window: &[F], periodic: &[F]) -> Vec<F> {
        self.transition_impl(window, periodic)
    }

    pub(super) fn transition_impl<F: Felt>(&self, window: &[F], _periodic: &[F]) -> Vec<F> {
        let s = &self.slots;
        let rd = |slot: usize| -> Ext2<F> { Ext2::new(window[2 * slot], window[2 * slot + 1]) };
        let base = |v: Fp| -> Ext2<F> { Ext2::from_base(v) };
        let one = Ext2::<F>::ONE;
        let mut res: Vec<Ext2<F>> = Vec::with_capacity(s.num_constraints());

        // The vanishing power tower: tower[k] = z^(2^(k+1)), so tower[k-1] = z^t.
        let z = rd(s.z());
        let mut prev = z;
        for k in 0..s.k {
            let zp = rd(s.tower(k));
            res.push(zp - prev * prev);
            prev = zp;
        }
        // z_h_inv * (z^t - 1) = 1.
        let z_h_inv = rd(s.z_h_inv());
        let zt = rd(s.tower(s.k - 1));
        res.push(z_h_inv * (zt - one) - one);
        // E = (z - g^(t-1)) * z_h_inv.
        let e = rd(s.e());
        res.push(e - (z - base(self.g_tm1)) * z_h_inv);

        if let Some(stmt) = &self.strip_stmt {
            // Strip mode: the products live in the strip region; here each
            // out pins to its acc cell plus the statement's linear part over
            // this region's own cells. Base input lane u is window column u.
            for i in 0..s.nt {
                let ev = |j: usize| -> F {
                    let mut acc = F::from_base(stmt[j].constant);
                    for (u, c) in &stmt[j].input_coeffs {
                        acc = acc + F::from_base(*c) * window[*u as usize];
                    }
                    acc
                };
                let stmt_v = Ext2::new(ev(2 * i), ev(2 * i + 1));
                res.push(rd(s.out(i)) - rd(s.acc(i)) - stmt_v);
            }
        } else {
            // Recompute every inner transition from the frame over Ext2<F> and
            // pin each witnessed value to it. The challenges come from this
            // region's cells, which the assembly binds to the inner transcript.
            let frame: Vec<Ext2<F>> = (0..s.w).map(|i| rd(s.frame(i))).collect();
            let per: Vec<Ext2<F>> = (0..s.p).map(|i| rd(s.periodic(i))).collect();
            let chal: Vec<Ext2<F>> = (0..s.ch).map(|i| rd(s.chal(i))).collect();
            let recomputed = self.air.transition_gen_at::<Ext2<F>>(&frame, &per, &chal);
            for (i, value) in recomputed.iter().take(s.nt).enumerate() {
                res.push(rd(s.out(i)) - *value);
            }
        }

        // Boundary quotients: q * (z - g^row) = frame[col] - expected.
        for (j, b) in self.boundaries.iter().enumerate() {
            let q = rd(s.quot(j));
            let denom = z - base(b.g_row);
            // A public word is read from its slot's low lane, as a base element;
            // the high lane is never read, so it cannot carry a different word.
            let expected = match self.public_of.get(j).copied().flatten() {
                Some(k) => Ext2::new(window[2 * s.pubw(k)], F::ZERO),
                None => base(b.expected),
            };
            let numer = rd(s.frame(b.col)) - expected;
            res.push(q * denom - numer);
        }

        // comp_z = sum coeff_i * out_i * E over the transitions, plus the batched
        // boundary quotients under their coefficients.
        let mut acc = Ext2::<F>::ZERO;
        for i in 0..s.nt {
            acc = acc + rd(s.coeff(i)) * rd(s.out(i)) * e;
        }
        for j in 0..s.b {
            acc = acc + rd(s.coeff(s.nt + j)) * rd(s.quot(j));
        }
        res.push(rd(s.comp_z()) - acc);

        let mut flat = Vec::with_capacity(res.len() * 2);
        for v in res {
            flat.push(v.c0);
            flat.push(v.c1);
        }
        flat
    }
}
