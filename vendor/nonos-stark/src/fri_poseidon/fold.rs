// NONOS Operating System (AGPL-3.0-or-later)

//! The FRI folding step over a coset, identical to the BLAKE3 FRI's fold.

use super::super::field::Fp;
use alloc::vec::Vec;

pub(super) fn fold_layer(evals: &[Fp], beta: Fp, shift: Fp, omega: Fp, inv2: Fp) -> Vec<Fp> {
    let half = evals.len() / 2;
    let (lo, hi) = evals.split_at(half);
    let mut out = Vec::with_capacity(half);
    let mut x = shift;
    for (a, b) in lo.iter().zip(hi.iter()) {
        let even = (*a + *b) * inv2;
        let odd = (*a - *b) * inv2 * x.inv();
        out.push(even + beta * odd);
        x = x * omega;
    }
    out
}
