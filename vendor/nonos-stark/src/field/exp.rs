// NONOS Operating System (AGPL-3.0-or-later)

//! Field exponentiation and inversion.

use super::element::{Fp, P};

impl Fp {
    #[inline]
    pub fn square(self) -> Fp {
        self * self
    }

    /// Exponentiation by square and multiply.
    pub fn pow(self, mut exp: u64) -> Fp {
        let mut base = self;
        let mut acc = Fp::ONE;
        while exp != 0 {
            if exp & 1 == 1 {
                acc = acc * base;
            }
            base = base.square();
            exp >>= 1;
        }
        acc
    }

    /// The multiplicative inverse via Fermat's little theorem, `a^(p-2)`.
    /// Returns `ZERO` for `ZERO`, which has no inverse; callers must exclude it.
    pub fn inv(self) -> Fp {
        self.pow(P - 2)
    }
}
