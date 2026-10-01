// NONOS Operating System (AGPL-3.0-or-later)
//! The chunked fold is the serial fold, element for element.
//!
//! `fold_ext` carries a running inverse of the evaluation point, which is the
//! one sequential dependency in it. Cutting the run into chunks and seeding
//! each with `shift^-1 * omega^-start` is only sound if that seed is the field
//! element the serial loop would have held there, and a fold that is off by a
//! factor still produces a codeword, still commits, still proves, and gives a
//! different proof. The digest of the emitted settlement artifact moved on the
//! first attempt, which is how this test came to exist.

use super::super::field::{Fp, Fp2};
use super::fold::fold_ext;
use alloc::vec::Vec;

/// The serial form, written out here rather than imported, because a test that
/// calls the thing it is testing proves nothing. This is the loop as it stood
/// before the chunking.
fn fold_ext_serial(evals: &[Fp2], beta: Fp2, shift: Fp, omega: Fp, inv2: Fp) -> Vec<Fp2> {
    let half = evals.len() / 2;
    let (lo, hi) = evals.split_at(half);
    let mut out = Vec::with_capacity(half);
    let omega_inv = omega.inv();
    let mut x_inv = shift.inv();
    for (a, b) in lo.iter().zip(hi.iter()) {
        let even = (*a + *b).mul_base(inv2);
        let odd = (*a - *b).mul_base(inv2).mul_base(x_inv);
        out.push(even + beta * odd);
        x_inv = x_inv * omega_inv;
    }
    out
}

fn codeword(n: usize) -> Vec<Fp2> {
    (0..n)
        .map(|i| Fp2 {
            c0: Fp::from_u64((i as u64) * 0x9E37_79B9_7F4A_7C15 % 0xFFFF_FFFF_0000_0001),
            c1: Fp::from_u64((i as u64) * 0xC2B2_AE3D_27D4_EB4F % 0xFFFF_FFFF_0000_0001),
        })
        .collect()
}

/// Across chunk boundaries and past them: the fold is run at sizes below one
/// chunk, exactly one chunk, and several, because a seeding error is invisible
/// in the first chunk and shows from the second onwards.
#[test]
fn the_chunked_fold_is_the_serial_fold() {
    let omega = super::root_of_unity(16);
    let shift = Fp::from_u64(7);
    let inv2 = Fp::from_u64(2).inv();
    let beta = Fp2 {
        c0: Fp::from_u64(0xDEAD_BEEF),
        c1: Fp::from_u64(0x1234_5678),
    };

    for log_n in [4u32, 10, 13, 14, 16] {
        let evals = codeword(1usize << log_n);
        let want = fold_ext_serial(&evals, beta, shift, omega, inv2);
        let got = fold_ext(&evals, beta, shift, omega, inv2);
        assert_eq!(
            got.len(),
            want.len(),
            "the fold changed its output length at 2^{log_n}"
        );
        for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
            assert_eq!(
                g, w,
                "the chunked fold differs from the serial one at 2^{log_n}, index {i}"
            );
        }
    }
}
