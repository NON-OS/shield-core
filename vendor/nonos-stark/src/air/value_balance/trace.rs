// NONOS Operating System (AGPL-3.0-or-later)

//! The witness for the value-balance region, and the list of cells the range region bounds.

use super::super::super::field::Fp;
use super::air::{ValueBalance, CARRY_BITS, CARRY_OFFSET, HI_MAX, LIMB_SHIFT, WIDTH};
use super::leg::Leg;
use alloc::vec;
use alloc::vec::Vec;

impl ValueBalance {
    /// Terms are supplied in the same order as `legs`, so the trace and the sign
    /// column cannot drift apart. Both sums, the carry and the room follow from
    /// the limbs.
    pub fn trace(&self, terms: &[(Fp, Fp)]) -> Vec<Fp> {
        let n = 1usize << self.log_t;
        let mut t = vec![Fp::ZERO; n * WIDTH];
        let (mut acc_lo, mut acc_hi) = (Fp::ZERO, Fp::ZERO);
        let mut s_lo: i128 = 0;
        for r in 0..n {
            let (lo, hi) = terms.get(r).copied().unwrap_or((Fp::ZERO, Fp::ZERO));
            let at = r * WIDTH;
            t[at] = acc_lo;
            t[at + 1] = lo;
            t[at + 2] = hi;
            t[at + 3] = lo + hi * Fp::from_u64(LIMB_SHIFT);
            t[at + 4] = acc_hi;
            t[at + 6] = Fp::from_u64(HI_MAX) - hi;
            let leg = self.legs.get(r).copied().unwrap_or(Leg::Pad);
            acc_lo = acc_lo + leg.sign() * lo;
            acc_hi = acc_hi + leg.sign() * hi;
            s_lo += match leg {
                Leg::Input => lo.value() as i128,
                Leg::Output => -(lo.value() as i128),
                Leg::Pad => 0,
            };
        }
        let carry = (s_lo >> 32) + CARRY_OFFSET as i128;
        t[self.close_row() * WIDTH + 5] = if carry >= 0 {
            Fp::from_u64(carry as u64)
        } else {
            Fp::ZERO - Fp::from_u64((-carry) as u64)
        };
        t
    }

    /// Every cell the range region bounds, as `(row, column, bits)`: each leg's
    /// low limb, high limb and high room at 32 bits, then the carry.
    pub fn ranged(&self) -> Vec<(usize, usize, u32)> {
        let mut v = Vec::new();
        for r in 0..self.close_row() {
            v.push((r, 1, 32));
            v.push((r, 2, 32));
            v.push((r, 6, 32));
        }
        v.push((self.close_row(), 5, CARRY_BITS));
        v
    }
}
