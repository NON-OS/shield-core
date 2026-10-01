//! The reference addition and subtraction.
//!
//! Both corrections are the same identity the multiply's reduction uses: a
//! carry past `2^64` is worth `EPSILON` too little and a borrow past it is
//! worth `EPSILON` too much. Neither can carry twice, because `2 * P` is above
//! `2^64` and no `u64` is two moduli above the range.

use super::consts::EPSILON;
use super::portable::canonical;

/// The reference addition.
#[inline]
pub fn add(a: u64, b: u64) -> u64 {
    let (s, carry) = a.overflowing_add(b);
    canonical(if carry { s.wrapping_add(EPSILON) } else { s })
}

/// The reference subtraction.
#[inline]
pub fn sub(a: u64, b: u64) -> u64 {
    let (d, borrow) = a.overflowing_sub(b);
    if borrow {
        d.wrapping_sub(EPSILON)
    } else {
        d
    }
}
