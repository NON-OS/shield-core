//! The field's two constants.
//!
//! `EPSILON` is the whole reason this field is fast: `2^64` is congruent to it,
//! so folding the high half of a product costs a shift, a mask, a multiply by
//! a constant and two conditional adds, with no division anywhere.

/// The Goldilocks modulus, `2^64 - 2^32 + 1`. Every value this module handles
/// is canonical, in `[0, P)`, which is what the prover's own field type holds.
pub const P: u64 = 0xFFFF_FFFF_0000_0001;

/// `2^64 - P`, which is `2^32 - 1`. It is the whole reason this field is fast:
/// `2^64` is congruent to `EPSILON`, so folding the high half of a product
/// costs one shift, one mask, one multiply by a constant and two conditional
/// adds, with no division anywhere.
pub const EPSILON: u64 = 0xFFFF_FFFF;
