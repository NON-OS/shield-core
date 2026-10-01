// NONOS Operating System (AGPL-3.0-or-later)

//! The coset passes the streaming prover shares. `trace_coeffs` interpolates the trace columns
//! to coefficients, `periodic_coeffs` does the same for the periodic columns, and `extend`
//! evaluates one coset of the low-degree extension from those coefficients on demand. Holding
//! coefficients and extending a coset at a time is what keeps the working set to one coset
//! rather than the whole extension, so every later pass, the commitment, the composition, the
//! DEEP polynomial, draws its coset through here instead of materializing the extension once.

use super::super::super::field::Fp;
use super::super::super::poly::{intt, lde_from_coeffs};
use super::setup::Domain;
use alloc::vec::Vec;

/// Row-major trace to per-column coefficient form. The coefficients are the
/// polynomial; every pass extends them onto whichever coset it is walking, so
/// nothing ever holds a column over the full evaluation domain.
pub(in crate::air) fn trace_coeffs(trace: &[Fp], d: &Domain) -> Vec<Vec<Fp>> {
    crate::par::map_index(d.width, |c| {
        let column: Vec<Fp> = (0..d.t).map(|i| trace[i * d.width + c]).collect();
        intt(&column, d.g)
    })
}

pub(in crate::air) fn periodic_coeffs(cols: &[Vec<Fp>], d: &Domain) -> Vec<Vec<Fp>> {
    crate::par::map_slice(cols, |col| intt(col, d.g))
}

/// Every column evaluated over coset `c`: row `i` of the result is position
/// `c + blowup * i` of the full domain.
pub(in crate::air) fn extend(coeffs: &[Vec<Fp>], d: &Domain, c: usize) -> Vec<Vec<Fp>> {
    let shift_c = d.coset_shift(c);
    crate::par::map_slice(coeffs, |cf| lde_from_coeffs(cf, shift_c, d.sub, d.t))
}
