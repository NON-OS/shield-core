// NONOS Operating System (AGPL-3.0-or-later)

//! The compose gadget's witness. Row 0 holds the frame, the periodic values,
//! the inner's challenges, the coefficients and the point, the witnessed
//! intermediates (vanishing tower, `z_h_inv`, `E`, the recomputed transitions,
//! the boundary quotients) and the claimed composition; row 1 is inert padding.

use super::super::super::field::{Fp, Fp2};
use super::super::spec::{Air, AirExt};
use super::gadget::ComposeCheckGen;
use super::generic::GenericTransition;
use alloc::vec::Vec;

impl<A: AirExt + GenericTransition> ComposeCheckGen<A> {
    pub fn trace(&self) -> Vec<Fp> {
        let s = &self.slots;
        let width = self.trace_width();
        let mut tr = alloc::vec![Fp::ZERO; 2 * width];
        let mut put = |slot: usize, v: Fp2| {
            tr[2 * slot] = v.c0;
            tr[2 * slot + 1] = v.c1;
        };

        for (i, v) in self.frame.iter().enumerate() {
            put(s.frame(i), *v);
        }
        for (i, v) in self.periodic.iter().enumerate() {
            put(s.periodic(i), *v);
        }
        for (i, v) in self.chal.iter().enumerate() {
            put(s.chal(i), *v);
        }
        put(s.z(), self.z);
        for (i, v) in self.coeffs.iter().enumerate() {
            put(s.coeff(i), *v);
        }

        let z = self.z;
        let z_h_inv = (z.pow(self.t) - Fp2::ONE).inv();
        put(s.z_h_inv(), z_h_inv);
        let e = (z - Fp2::from_base(self.g_tm1)) * z_h_inv;
        put(s.e(), e);

        let out = self.air.transition_ext(&self.frame, &self.periodic);
        for (i, v) in out.iter().enumerate() {
            put(s.out(i), *v);
        }
        if let Some(stmt) = &self.strip_stmt {
            // acc = out - statement, per base lane; the strip's totals land
            // here through the cycle. Lane u is frame, then periodic, then
            // challenge, the order the recording numbered its inputs.
            let lane = |u: usize| -> Fp {
                let (slot, l) = (u / 2, u % 2);
                let v = if slot < s.w {
                    self.frame[slot]
                } else if slot < s.w + s.p {
                    self.periodic[slot - s.w]
                } else {
                    self.chal[slot - s.w - s.p]
                };
                if l == 0 {
                    v.c0
                } else {
                    v.c1
                }
            };
            for i in 0..s.nt {
                let mut sc0 = stmt[2 * i].constant;
                for (u, c) in &stmt[2 * i].input_coeffs {
                    sc0 = sc0 + *c * lane(*u as usize);
                }
                let mut sc1 = stmt[2 * i + 1].constant;
                for (u, c) in &stmt[2 * i + 1].input_coeffs {
                    sc1 = sc1 + *c * lane(*u as usize);
                }
                put(
                    s.acc(i),
                    Fp2 {
                        c0: out[i].c0 - sc0,
                        c1: out[i].c1 - sc1,
                    },
                );
            }
        }
        put(s.comp_z(), self.comp_z);

        for (j, b) in self.boundaries.iter().enumerate() {
            let q = (self.frame[b.col] - Fp2::from_base(b.expected))
                * (z - Fp2::from_base(b.g_row)).inv();
            put(s.quot(j), q);
        }

        let mut zp = z;
        for k in 0..s.k {
            zp = zp.square();
            put(s.tower(k), zp);
        }
        for (k, w) in self.public_words.iter().enumerate() {
            put(s.pubw(k), Fp2::from_base(*w));
        }
        tr
    }
}
