// NONOS Operating System (AGPL-3.0-or-later)

//! The field modulus and the canonical element type.

/// The Goldilocks modulus, 2^64 - 2^32 + 1.
pub const P: u64 = 0xFFFF_FFFF_0000_0001;

/// 2^32 - 1, equal to 2^64 - P, used by the add and subtract carry corrections.
pub(super) const EPSILON: u64 = 0xFFFF_FFFF;

/// A canonical field element, always held in the range `[0, P)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fp(pub(super) u64);

impl Fp {
    /// The canonical representative, for serializers and registration
    /// constants that leave the crate.
    pub fn to_u64(self) -> u64 {
        self.0
    }
}

impl Fp {
    pub const ZERO: Fp = Fp(0);
    pub const ONE: Fp = Fp(1);

    /// Reduce an arbitrary `u64` into the canonical range. A single conditional
    /// subtraction suffices because `2^64 - P = EPSILON < P`.
    #[inline]
    pub const fn from_u64(x: u64) -> Fp {
        Fp(if x >= P { x - P } else { x })
    }

    /// The canonical representative in `[0, P)`.
    #[inline]
    pub const fn value(self) -> u64 {
        self.0
    }
}
