// NONOS Operating System (AGPL-3.0-or-later)

//! Evaluation of a polynomial given in coefficient form, low degree first.

use super::super::field::{Fp, Fp2};

/// Evaluate `coeffs[0] + coeffs[1] x + coeffs[2] x^2 + ...` at `x` by Horner's
/// method. An empty coefficient list is the zero polynomial.
pub fn eval(coeffs: &[Fp], x: Fp) -> Fp {
    let mut acc = Fp::ZERO;
    for &c in coeffs.iter().rev() {
        acc = acc * x + c;
    }
    acc
}

/// Evaluate a base-coefficient polynomial at an extension point, `Fp2` in and out.
/// A STARK draws its out-of-domain sampling point from `Fp2` for soundness, so the
/// trace columns, whose coefficients are base-field, are evaluated there through
/// this. On a base-embedded `x` it agrees with `eval` embedded, by construction.
pub fn eval_ext(coeffs: &[Fp], x: Fp2) -> Fp2 {
    let mut acc = Fp2::ZERO;
    for &c in coeffs.iter().rev() {
        acc = acc * x + Fp2::from_base(c);
    }
    acc
}
