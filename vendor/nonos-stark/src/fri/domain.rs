// NONOS Operating System (AGPL-3.0-or-later)

//! The evaluation domain: a multiplicative subgroup of size a power of two.

use super::super::field::{Fp, P};

/// A multiplicative generator of the Goldilocks field. Every nonzero element is
/// a power of it, so `GENERATOR^((P-1)/2^k)` has order exactly `2^k`.
const GENERATOR: u64 = 7;

/// A primitive `2^log_n`-th root of unity. The returned `omega` generates the
/// size-`2^log_n` subgroup used as the FRI evaluation domain: `omega^(2^log_n)`
/// is one and `omega^(2^(log_n-1))` is minus one, so the domain is closed under
/// negation, which is what the folding step requires. Valid for `log_n <= 32`,
/// the two-adicity of this field.
pub fn root_of_unity(log_n: u32) -> Fp {
    Fp::from_u64(GENERATOR).pow((P - 1) >> log_n)
}
