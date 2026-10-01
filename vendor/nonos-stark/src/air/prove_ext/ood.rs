// NONOS Operating System (AGPL-3.0-or-later)

//! Drawing the out-of-domain point. The verifier samples one point in the extension field to
//! test the composition away from the trace domain, and the draw rejects any point that lands
//! in the domain, so no divisor in the composition vanishes. The point comes from the
//! transcript, so prover and verifier draw the same one, and its being off the domain is what
//! makes the low-degree test sound: agreement at a random off-domain point forces the
//! polynomial identity by the Schwartz-Zippel bound.

use super::super::super::field::{Fp, Fp2};
use super::super::super::transcript::Transcript;

/// Draw the out-of-domain point from the extension: off the evaluation coset and
/// off the trace domain, so every DEEP and periodic denominator is invertible in
/// `Fp2`. Both sides run this identically, so they agree on the point.
pub(in crate::air) fn draw_ood_point_ext(
    transcript: &mut Transcript,
    shift: Fp,
    n: usize,
    t: usize,
) -> Fp2 {
    let shift_n = Fp2::from_base(shift.pow(n as u64));
    let mut z = transcript.challenge_fp2();
    while z.pow(n as u64) == shift_n || z.pow(t as u64) == Fp2::ONE {
        z = transcript.challenge_fp2();
    }
    z
}
