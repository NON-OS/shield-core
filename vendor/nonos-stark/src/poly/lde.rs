// NONOS Operating System (AGPL-3.0-or-later)

//! The low-degree extension by transform: interpolate values on the trace
//! subgroup, then evaluate the same polynomial on a larger coset. This is the
//! per-column extension the prover runs, in O(n log n).

use super::super::field::Fp;
use super::ntt::{intt, ntt};
use alloc::vec::Vec;

/// Extend `values`, the evaluations of a polynomial on the size-`values.len()`
/// subgroup `{trace_gen^i}`, onto the coset `shift * {coset_gen^i}` of size
/// `target_len`. `trace_gen` and `coset_gen` are primitive roots of unity of the
/// respective orders. The result equals evaluating the interpolating polynomial
/// at each coset point, computed by transform rather than point by point.
pub fn lde(values: &[Fp], trace_gen: Fp, shift: Fp, coset_gen: Fp, target_len: usize) -> Vec<Fp> {
    lde_from_coeffs(&intt(values, trace_gen), shift, coset_gen, target_len)
}

/// The same extension, from coefficients already in hand. A caller evaluating one
/// polynomial over many cosets interpolates once and calls this per coset, rather
/// than paying the interpolation again for every one of them.
pub fn lde_from_coeffs(coeffs: &[Fp], shift: Fp, coset_gen: Fp, target_len: usize) -> Vec<Fp> {
    // Evaluate `P(x) = sum coeffs[j] x^j` on the coset `shift * {coset_gen^i}` for
    // `i` in `0..target_len`.
    //
    // The domain is split into `m` cosets of the subgroup of order `L`, the
    // smallest power of two that holds the coefficients: point `i = a + m b` is
    // `(shift coset_gen^a) (coset_gen^m)^b`, and `coset_gen^m` has order `L`. On
    // coset `a` the term `x^j` is `(shift coset_gen^a)^j (coset_gen^m)^(b (j mod
    // L))`, so coefficient `j` lands on residue `j mod L` with weight
    // `(shift coset_gen^a)^j`, and one transform of size `L` evaluates the whole
    // coset. That is `target_len log L` butterflies where one transform of the
    // whole domain was `target_len log target_len`, and a transform of size `L`
    // stays in cache where one of the domain does not.
    //
    // Folding the high coefficients onto their residue, rather than dropping
    // them, is what evaluates a polynomial longer than `L` correctly, which a
    // blinded column `f + r * Z_H` is when `L` is the trace length.
    let l = coeffs.len().next_power_of_two().clamp(1, target_len.max(1));
    let m = target_len / l;
    let step = coset_gen.pow(m as u64);
    let mut out = alloc::vec![Fp::ZERO; target_len];
    let mut base = shift;
    for a in 0..m {
        let mut c = alloc::vec![Fp::ZERO; l];
        let mut s = Fp::ONE;
        for (j, &cj) in coeffs.iter().enumerate() {
            let k = j & (l - 1);
            c[k] = c[k] + cj * s;
            s = s * base;
        }
        for (b, v) in ntt(&c, step).into_iter().enumerate() {
            out[a + m * b] = v;
        }
        base = base * coset_gen;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fri::root_of_unity;
    use crate::poly::eval;

    /// Every point of the extension is the polynomial's value there, for a
    /// polynomial shorter than the domain, one exactly its length, one longer
    /// than the trace (a blinded column), and one far longer than the trace (a
    /// mask column). Checked against direct evaluation at every point.
    #[test]
    fn the_coset_extension_is_the_polynomial() {
        let log_n = 10u32;
        let n = 1usize << log_n;
        let omega = root_of_unity(log_n);
        let shift = Fp::from_u64(7);
        for len in [1usize, 5, 64, 64 + 9, 512, n, n + 9] {
            let coeffs: Vec<Fp> = (0..len).map(|j| Fp::from_u64((j as u64 * 2654435761) ^ 0x9e37)).collect();
            let got = lde_from_coeffs(&coeffs, shift, omega, n);
            for (i, v) in got.iter().enumerate() {
                let x = shift * omega.pow(i as u64);
                assert!(*v == eval(&coeffs, x), "length {len}: point {i} is not the polynomial's value");
            }
        }
    }
}
