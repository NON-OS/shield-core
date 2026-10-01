//! One transform butterfly.

use super::dispatch::{add, sub};

/// The sum and difference of a pair together, so the transform loads each pair once.
#[inline]
pub fn butterfly(a: u64, b: u64) -> (u64, u64) {
    (add(a, b), sub(a, b))
}
