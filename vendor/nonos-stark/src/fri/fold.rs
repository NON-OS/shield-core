// NONOS Operating System (AGPL-3.0-or-later)

//! The FRI folding step. A codeword of `f` on a domain `D = shift * {omega^i}`
//! folds with a challenge into a codeword of a half-degree polynomial on the
//! squared domain. The domain may be a coset (`shift != 1`), which is what the
//! STARK needs so the low-degree test runs off the trace domain.

use super::super::field::{Fp, Fp2};
use alloc::vec::Vec;

/// Fold `evals`, the values of `f` on the size-`n` domain `{shift*omega^i}`, into
/// the values of `f_beta` on the size-`n/2` squared domain. Writing
/// `f(x) = E(x^2) + x*O(x^2)`, the even and odd parts are recovered from the pair
/// `(f(x), f(-x))` and recombined as `E + beta*O`. `inv2` is the inverse of two,
/// passed in so it is computed once by the caller.
pub fn fold_layer(evals: &[Fp], beta: Fp, shift: Fp, omega: Fp, inv2: Fp) -> Vec<Fp> {
    let half = evals.len() / 2;
    let (lo, hi) = evals.split_at(half);
    let mut out = Vec::with_capacity(half);
    // x walks the first half of the domain: shift, shift*omega, ... The point
    // paired with x is -x = shift*omega^(i + n/2), which sits at `hi[i]`.
    /*
     * The odd part divides by x = shift * omega^i. Its inverse is shift^-1 *
     * omega^-i, so it is walked as a running product from one inversion of shift
     * and one of omega, rather than inverting x afresh at every point. A field
     * inversion costs on the order of a hundred multiplications, and the values
     * are identical, since the inverse of a product is the product of the inverses.
     */
    let omega_inv = omega.inv();
    let mut x_inv = shift.inv();
    for (a, b) in lo.iter().zip(hi.iter()) {
        let even = (*a + *b) * inv2;
        let odd = (*a - *b) * inv2 * x_inv;
        out.push(even + beta * odd);
        x_inv = x_inv * omega_inv;
    }
    out
}

/// The first fold, from the base-field layer 0 to an extension codeword, under an
/// extension challenge. The even and odd parts are base-field values, computed
/// exactly as in `fold_layer`; combining them with an extension `beta` lifts the
/// result into `Fp2`. Drawing the fold challenge from `Fp2` is what raises the FRI
/// soundness error from ~2^-64 to ~2^-128 (see `Nonos.Stark.Soundness`). On a base
/// `beta` this reproduces `fold_layer` embedded, so it is a faithful extension.
pub fn fold_first(evals: &[Fp], beta: Fp2, shift: Fp, omega: Fp, inv2: Fp) -> Vec<Fp2> {
    let half = evals.len() / 2;
    let (lo, hi) = evals.split_at(half);
    let mut out = Vec::with_capacity(half);
    // The running inverse of x, as in `fold_layer`.
    let omega_inv = omega.inv();
    let mut x_inv = shift.inv();
    for (a, b) in lo.iter().zip(hi.iter()) {
        let even = (*a + *b) * inv2;
        let odd = (*a - *b) * inv2 * x_inv;
        out.push(Fp2::from_base(even) + beta.mul_base(odd));
        x_inv = x_inv * omega_inv;
    }
    out
}

/// A fold on an extension codeword under an extension challenge: every folded FRI
/// layer past the first is `Fp2`-valued, so this is the step the remaining folds
/// use. The evaluation-point arithmetic stays in the base field; only the codeword
/// values and the challenge live in the extension.
pub fn fold_ext(evals: &[Fp2], beta: Fp2, shift: Fp, omega: Fp, inv2: Fp) -> Vec<Fp2> {
    let half = evals.len() / 2;
    let (lo, hi) = evals.split_at(half);
    let omega_inv = omega.inv();
    let shift_inv = shift.inv();

    /*
     * The running inverse of x is a sequential dependency and it is the only
     * one here: every output is otherwise a function of its own pair. So the
     * run is cut into chunks, each seeded with `shift^-1 * omega^-start` and
     * stepped the same way inside.
     *
     * Byte identical, not approximately so. `omega_inv.pow(start)` is the same
     * field element as `start` multiplications of `omega_inv`, and each output
     * is computed from its own inputs with no sum reassociated across chunks.
     * The emitted settlement proof's digest is the gate on that claim.
     *
     * This is on the shared fold, so both FRIs get it. The Poseidon one had no
     * parallel call at all, which is why committing the outer under it ran on
     * one core of a hundred and twenty eight.
     */
    let chunk = 1usize << 12;
    let n_chunks = half.div_ceil(chunk.max(1)).max(1);
    let parts = crate::par::map_index(n_chunks, |c| {
        let start = c * chunk;
        let end = (start + chunk).min(half);
        let mut x_inv = shift_inv * omega_inv.pow(start as u64);
        let mut part = Vec::with_capacity(end.saturating_sub(start));
        for i in start..end {
            let (a, b) = (lo[i], hi[i]);
            let even = (a + b).mul_base(inv2);
            let odd = (a - b).mul_base(inv2).mul_base(x_inv);
            part.push(even + beta * odd);
            x_inv = x_inv * omega_inv;
        }
        part
    });

    let mut out = Vec::with_capacity(half);
    for part in parts {
        out.extend(part);
    }
    out
}
