// NONOS Operating System (AGPL-3.0-or-later)

//! Drawing the out-of-domain point for the Poseidon-committed prover and verifier.

use super::super::field::{Fp, Fp2};
use super::super::poseidon_transcript::PoseidonTranscript;

/// Whether a drawn point is usable: off the coset and off the trace domain,
/// so every DEEP and periodic denominator is invertible. A recorder that
/// mirrors the transcript redraws on the same rule.
pub fn ood_point_ok(z: Fp2, shift: Fp, n: usize, t: usize) -> bool {
    let shift_n = Fp2::from_base(shift.pow(n as u64));
    z.pow(n as u64) != shift_n && z.pow(t as u64) != Fp2::ONE
}

/// The out-of-domain point from the Poseidon transcript, redrawn until it is
/// usable. Both prover and verifier run this identically, so they agree.
pub(super) fn draw_ood_point_poseidon(
    transcript: &mut PoseidonTranscript,
    shift: Fp,
    n: usize,
    t: usize,
) -> Fp2 {
    let mut z = transcript.challenge_fp2();
    while !ood_point_ok(z, shift, n, t) {
        z = transcript.challenge_fp2();
    }
    z
}
