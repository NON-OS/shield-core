// NONOS Operating System (AGPL-3.0-or-later)

//! `Fp2` written as pairs over any field, for a copy constraint argued at
//! extension challenges.
//!
//! The trace is over `Fp` and the constraints are evaluated over `Fp` on the
//! domain and over `Fp2` at the out-of-domain point. A relation with `Fp2`
//! challenges is two relations with `Fp` coefficients, its components, and a
//! pair `(a, b)` standing for `a + b X`, `X^2 = 7`, computes both at once over
//! whichever field the cells are in. A polynomial with `Fp2` coefficients
//! vanishes on the trace domain, which lies in `Fp`, if and only if both
//! components do, so the two constraints say what the one would.

use super::super::super::field::{Felt, Fp};

/// The nonresidue `Fp2` is built over: `X^2 = 7`.
const W: u64 = 7;

#[derive(Clone, Copy)]
pub(super) struct Pair<F: Felt>(pub F, pub F);

impl<F: Felt> Pair<F> {
    pub(super) fn one() -> Self {
        Pair(F::ONE, F::ZERO)
    }

    pub(super) fn add(self, o: Self) -> Self {
        Pair(self.0 + o.0, self.1 + o.1)
    }

    pub(super) fn sub(self, o: Self) -> Self {
        Pair(self.0 - o.0, self.1 - o.1)
    }

    /// `(a + b X)(c + d X) = (a c + 7 b d) + (a d + b c) X`.
    pub(super) fn mul(self, o: Self) -> Self {
        let w = F::from_base(Fp::from_u64(W));
        Pair(self.0 * o.0 + w * self.1 * o.1, self.0 * o.1 + self.1 * o.0)
    }

    /// Both components times a value of the evaluation field.
    pub(super) fn scale(self, k: F) -> Self {
        Pair(self.0 * k, self.1 * k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::Fp2;

    /// The pair product is `Fp2`'s product, on values that exercise the
    /// nonresidue.
    #[test]
    fn a_pair_multiplies_as_fp2() {
        let (a, b) = (Fp2::new(Fp::from_u64(3), Fp::from_u64(11)), Fp2::new(Fp::from_u64(5), Fp::from_u64(13)));
        let p = Pair::<Fp>(a.c0, a.c1).mul(Pair(b.c0, b.c1));
        let want = a * b;
        assert!(p.0 == want.c0 && p.1 == want.c1, "the pair product is not the Fp2 product");
    }
}
