// NONOS Operating System (AGPL-3.0-or-later)

//! The value-balance region and its transition. A row carries seven cells: the running signed
//! sum of low limbs, the leg's two value limbs, the recomposed value, the running signed sum of
//! high limbs, on the closing row the carry between the two sums, and the high limb's room
//! below its bound. The leg sign rides a public periodic column, so a prover cannot relabel an
//! output row as an input.
//!
//! Conservation holds over the integers, not only modulo p. `LimbRange` bounds every limb and
//! every room below 2^32 and the carry below 8. The room bounds the high limb by 2^32 - 2, so
//! every value lies in [0, p - 1) and its field and integer values agree. The low sum lies in
//! (-2^34, 2^33), so the closing constraints `S_lo = c 2^32` and `S_hi = -c` hold as integer
//! equations and `S_lo + 2^32 S_hi = 0`. See docs/03-keys-notes-nullifiers.md.

use super::super::super::field::{Felt, Fp};
use super::leg::Leg;
use alloc::vec;
use alloc::vec::Vec;

/// The scale between a note's two value limbs.
pub const LIMB_SHIFT: u64 = 1u64 << 32;

/// The offset that makes the carry a nonnegative range-checked cell: the low
/// sum's carry lies in [-3, 1], so the cell holds `carry + 3` in [0, 4].
pub const CARRY_OFFSET: u64 = 3;

/// Bits the carry cell is range-checked to.
pub const CARRY_BITS: u32 = 3;

/// The largest high limb: `2^32 - 2`, so a value is at most `p - 2`.
pub const HI_MAX: u64 = (1u64 << 32) - 2;

/// Columns: signed low sum, low limb, high limb, value, signed high sum, carry,
/// high room.
pub const WIDTH: usize = 7;

/// A note commits its value as two limbs and a copy constraint moves a cell
/// rather than scaling one, so recomposition and conservation ride one
/// constraint. That keeps the limbs as raw cells a caller can bind against.
#[derive(Clone)]
pub struct ValueBalance {
    pub log_t: u32,
    pub legs: Vec<Leg>,
}

impl ValueBalance {
    /// Column three carries the recomposed value, so a caller can bind the whole
    /// amount to a public word. A copy constraint cannot scale a cell, so the
    /// recomposition has to be a constraint rather than a binding.
    /// The transition over any field, for in-circuit recomputation.
    pub fn transition_gen<F: Felt>(&self, window: &[F], periodic: &[F]) -> Vec<F> {
        self.transition_impl(window, periodic)
    }

    pub(super) fn transition_impl<F: Felt>(&self, window: &[F], periodic: &[F]) -> Vec<F> {
        let (acc_lo, lo, hi, value, acc_hi, carry, room) =
            (window[0], window[1], window[2], window[3], window[4], window[5], window[6]);
        let (next_lo, next_hi) = (window[WIDTH], window[WIDTH + 4]);
        let (sign, close) = (periodic[0], periodic[1]);
        let shift = F::from_base(Fp::from_u64(LIMB_SHIFT));
        let c = carry - F::from_base(Fp::from_u64(CARRY_OFFSET));
        vec![
            value - lo - hi * shift,
            room + hi - F::from_base(Fp::from_u64(HI_MAX)),
            next_lo - acc_lo - sign * lo,
            next_hi - acc_hi - sign * hi,
            close * (acc_lo - c * shift),
            close * (acc_hi + c),
        ]
    }

    /// The row the closing constraints read: the first row after the legs,
    /// where both sums are complete.
    pub fn close_row(&self) -> usize {
        self.legs.iter().filter(|l| **l != Leg::Pad).count()
    }

    pub(super) fn closes(&self) -> Vec<Fp> {
        let mut c = vec![Fp::ZERO; 1usize << self.log_t];
        c[self.close_row()] = Fp::ONE;
        c
    }

    pub(super) fn signs(&self) -> Vec<Fp> {
        let n = 1usize << self.log_t;
        let mut s = vec![Fp::ZERO; n];
        for (r, v) in s.iter_mut().enumerate() {
            *v = self.legs.get(r).copied().unwrap_or(Leg::Pad).sign();
        }
        s
    }
}
