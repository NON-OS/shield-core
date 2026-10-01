//! The reference multiply, and the version that ships. It uses the prover's fold, replacing
//! `2^64` with `EPSILON` and `2^96` with `-1`, landing in canonical `[0, P)`. If the assembly
//! kernel ever disagrees, this version is right.

use super::consts::{EPSILON, P};

/// A 128 bit product folded with `2^64 = 2^32 - 1 (mod P)`, then canonicalised.
#[inline]
pub fn mul(a: u64, b: u64) -> u64 {
    reduce128(u128::from(a) * u128::from(b))
}

#[inline]
pub fn reduce128(x: u128) -> u64 {
    let lo = x as u64;
    let hi = (x >> 64) as u64;
    let hi_hi = hi >> 32;
    let hi_lo = hi & EPSILON;

    // Split at 32 bits: the top word subtracts (2^96 is -1), the bottom multiplies by EPSILON.
    let (mut t, borrow) = lo.overflowing_sub(hi_hi);
    if borrow {
        t = t.wrapping_sub(EPSILON);
    }
    let (mut t, carry) = t.overflowing_add(hi_lo * EPSILON);
    if carry {
        t = t.wrapping_add(EPSILON);
    }
    canonical(t)
}

/// A single conditional subtraction suffices: `2 * P` exceeds `2^64`.
#[inline]
pub fn canonical(x: u64) -> u64 {
    if x >= P {
        x - P
    } else {
        x
    }
}
