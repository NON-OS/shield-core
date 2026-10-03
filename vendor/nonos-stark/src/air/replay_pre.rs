// NONOS Operating System (AGPL-3.0-or-later)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! The preprocessed transcript's prefix, replayed to the composition at z.
//!
//! `stark_verify_ext_preprocessed` draws the composition coefficients and the
//! out-of-domain point before it looks at a query, and the point it draws
//! depends on the evaluation domain, which depends on the rate the proof was
//! made at. `replay_challenges_ext` replays the unblown transcript, so for a
//! proof at any other rate its z is a point the proof never opened and its
//! `comp_z` is the composition there. This replays the same prefix at the
//! proof's own rate and stops once `comp_z` is known, because that is the one
//! value a chain verifier is still handed rather than derives, and the value
//! an emitter has to print beside the proof it belongs to.
//!
//! Nothing here is a second opinion. The transcript label, the draw order and
//! the composition are the verifier's own calls in the verifier's own order;
//! a proof this disagrees with is a proof the verifier rejects.
//!
//! There are two draw orders because there are two commitment shapes, and the
//! one round form was run over a two round artifact. It did not fail. It is
//! honest arithmetic over a transcript nobody ran, and the z it printed was
//! carried into another lane and believed, where it was read back as evidence
//! that the outer draws no challenges at all. So the one round entry refuses a
//! two round proof rather than answering for it.

use super::super::field::{Fp, Fp2};
use super::super::fri::root_of_unity;
use super::super::transcript::Transcript;
use super::composition::{compose_ext, domain_params_blown, num_coeffs};
use super::prove_ext::{draw_ood_point_ext, COSET_SHIFT};
use super::rounds::Permuted;
use super::spec::AirExt;
use super::wire::types_ext_pre::StarkProofExtPre;
use alloc::vec::Vec;

/// What the transcript absorbs before the out-of-domain point, and the domain
/// the point is drawn over.
///
/// A struct because the three roots are three digests of the same type and the
/// three domain numbers are three lengths of the same type, and a call site
/// with six positional arguments of two types is a transposition waiting to
/// happen in the one function where order is the whole meaning.
pub struct Prefix<'a> {
    pub publics: &'a [Fp],
    pub trace_root: &'a [u8; 32],
    /// The second round's root, or `None` for a one round proof. There is no
    /// default: the caller is the only one who knows, and the version that
    /// assumed `None` answered for a two round artifact with a point no proof
    /// had opened.
    pub perm_root: Option<&'a [u8; 32]>,
    pub comp_root: &'a [u8; 32],
    pub n_coeffs: usize,
    pub shift: Fp,
    /// Evaluation domain size, then trace length.
    pub n: usize,
    pub t: usize,
    /// Base-field lanes per copy-constraint challenge, the AIR's
    /// `challenge_lanes`: one for `challenge_fp`, two for `challenge_fp2`.
    pub challenge_lanes: usize,
}

/// Beta then gamma off a Keccak transcript, in `Fp` or `Fp2` as `lanes` says.
/// The prover and every replay draw through this, so they read the same tags.
pub fn draw_rounds_challenges_keccak(ts: &mut Transcript, lanes: usize) -> (Fp2, Fp2) {
    if lanes == 2 {
        (ts.challenge_fp2(), ts.challenge_fp2())
    } else {
        (
            Fp2::from_base(ts.challenge_fp()),
            Fp2::from_base(ts.challenge_fp()),
        )
    }
}

/// The composition coefficients. The launch circuit, the one argued in `Fp2`,
/// draws them as powers of one alpha. The settlement outer draws each on its
/// own, as the verifier deployed for it replays.
pub fn draw_composition_coeffs(ts: &mut Transcript, n: usize, lanes: usize) -> Vec<Fp2> {
    if lanes == 2 {
        ts.challenge_powers(n)
    } else {
        (0..n).map(|_| ts.challenge_fp2()).collect()
    }
}

/// The DEEP coefficients, by the same rule as the composition's: powers of one
/// alpha on the launch transcript, independent draws on the settlement outer's.
/// One quotient per frame value, one for the composition, one per periodic
/// claim, and the batching argument is the composition's.
pub fn draw_deep_coeffs(ts: &mut Transcript, n: usize, lanes: usize) -> Vec<Fp2> {
    draw_composition_coeffs(ts, n, lanes)
}

/// The DEEP round as the prover runs it. v1: the coefficients as
/// `draw_deep_coeffs` draws them, and a zero nonce that never reaches the wire.
/// On the format 7 transcript (docs/17 steps 8 and 9): a `DEEP_GRIND_BITS`
/// grind, its nonce absorbed, then `n` independent coefficients from the exact
/// stream under 0x09. Independent coefficients make the batch an affine space,
/// one line's error, which the grind lifts past 80 bits.
pub fn draw_deep_coeffs_ground(ts: &mut Transcript, n: usize, lanes: usize) -> (Vec<Fp2>, u64) {
    #[cfg(feature = "fri8")]
    if lanes == 2 {
        let nonce = ts.grind(super::super::fri_ext::DEEP_GRIND_BITS);
        return (ts.stream_fp2(0x09, n), nonce);
    }
    (draw_deep_coeffs(ts, n, lanes), 0)
}

/// The DEEP round as a verifier replays it: on the format 7 transcript the nonce must meet the
/// grind, bound where the prover bound it, before the stream is drawn. `None`
/// when it does not. On v1 the nonce is not part of the proof and is ignored.
pub fn draw_deep_coeffs_checked(
    ts: &mut Transcript,
    n: usize,
    lanes: usize,
    nonce: u64,
) -> Option<Vec<Fp2>> {
    #[cfg(feature = "fri8")]
    if lanes == 2 {
        if !ts.verify_pow(nonce, super::super::fri_ext::DEEP_GRIND_BITS) {
            return None;
        }
        return Some(ts.stream_fp2(0x09, n));
    }
    let _ = nonce;
    Some(draw_deep_coeffs(ts, n, lanes))
}

/// Bits of proof-of-work before each FRI folding challenge: the launch rule on
/// the launch transcript, none on the settlement outer's.
pub fn commit_grind_bits(lanes: usize) -> u32 {
    if lanes == 2 {
        super::super::fri_ext::COMMIT_GRIND_BITS
    } else {
        0
    }
}

/// How many chained searches the query grind is split into: the launch rule
/// on the launch transcript, one on the settlement outer's.
pub fn grind_chunks(lanes: usize) -> u32 {
    if lanes == 2 {
        super::super::fri_ext::GRIND_CHUNKS
    } else {
        1
    }
}

/// X, the generator of F_p^2 over F_p, with X^2 = 7.
fn ext_generator() -> Fp2 {
    Fp2::new(Fp::ZERO, Fp::ONE)
}

/*
 * The mask pair as one F_p^2 polynomial.
 *
 * The two mask columns M_a and M_b are base-field and uniform, so
 * N = M_a + X M_b is a uniform F_p^2 polynomial. On the launch transcript the
 * frame opens N at each window point instead of M_a and M_b apart: slot a
 * carries N(z_k) and slot b carries zero, which the verifier requires. DEEP
 * gives column b the coefficient X times column a's, so the mask's part of
 * the DEEP polynomial is a_k (N(x) - N(z_k)) / (x - z_k): F_p^2-linear in N
 * end to end, which is what makes the zero-knowledge rank condition a rank
 * over F_p^2 (docs/12-zero-knowledge.md Section 4.4). The frame's length and every
 * offset in the proof are unchanged.
 */

/// Fold the mask pair's frame slots: N(z_k) into slot a, zero into slot b.
pub fn mask_pair_frame(frame: &mut [Fp2], width: usize, window: usize, pair: (usize, usize)) {
    let x = ext_generator();
    for k in 0..window {
        let (a, b) = (k * width + pair.0, k * width + pair.1);
        frame[a] = frame[a] + x * frame[b];
        frame[b] = Fp2::ZERO;
    }
}

/// Whether the frame's second mask slots are zero, as the prover writes them.
pub fn mask_pair_canonical(
    frame: &[Fp2],
    width: usize,
    window: usize,
    pair: (usize, usize),
) -> bool {
    (0..window).all(|k| frame[k * width + pair.1] == Fp2::ZERO)
}

/// Column b's DEEP coefficient becomes X times column a's, per window row.
pub fn mask_pair_coeffs(deep: &mut [Fp2], width: usize, window: usize, pair: (usize, usize)) {
    let x = ext_generator();
    for k in 0..window {
        deep[k * width + pair.1] = deep[k * width + pair.0] * x;
    }
}

/// Adopt a drawn pair at the AIR's width.
pub fn adopt_pair<A: AirExt + Permuted>(air: &mut A, beta: Fp2, gamma: Fp2) {
    if air.challenge_lanes() == 2 {
        air.set_challenges_ext(beta, gamma);
    } else {
        air.set_challenges(beta.c0, gamma.c0);
    }
}

/// The transcript up to the out-of-domain point: the publics, the trace root,
/// the second round if there is one, the composition coefficients, the
/// composition root, and the point.
///
/// One function because there is one order, and the day it lived in two places
/// one of them was run over an artifact from the other and printed a point no
/// proof had opened. The prover writes it a third time and that copy is next.
///
/// Returns the challenges the two rounds drew, the coefficients, and `z`.
pub fn transcript_to_z(ts: &mut Transcript, p: &Prefix) -> (Option<(Fp2, Fp2)>, Vec<Fp2>, Fp2) {
    ts.absorb_fp_vec(p.publics);
    ts.absorb_digest(p.trace_root);
    /*
     * Round two. The challenges come out against the region root and the
     * permutation root goes in before a single coefficient is drawn, so all
     * three move the sponge and a replay that skips them lands somewhere else
     * entirely.
     */
    let challenges = p.perm_root.map(|perm_root| {
        let pair = draw_rounds_challenges_keccak(ts, p.challenge_lanes);
        ts.absorb_digest(perm_root);
        pair
    });
    let coeffs = draw_composition_coeffs(ts, p.n_coeffs, p.challenge_lanes);
    ts.absorb_digest(p.comp_root);
    let z = draw_ood_point_ext(ts, p.shift, p.n, p.t);
    (challenges, coeffs, z)
}

/// What the transcript had drawn by the time the composition at z was fixed.
pub struct ReplayedPre {
    /// The composition coefficients, in draw order: transitions first, then
    /// boundaries, the order the emitted lists are paired against.
    pub coeffs: Vec<Fp2>,
    pub z: Fp2,
    pub comp_z: Fp2,
    /// The copy constraint's pair, when the proof committed in two rounds.
    /// Returned so a caller can state in its own output what it evaluated at.
    pub challenges: Option<(Fp2, Fp2)>,
    /// The seed the STARK transcript hands FRI after the DEEP draw: what FRI's
    /// positions, and so the consistency check's, are drawn under.
    pub seed: [u8; 32],
    /// The DEEP coefficients, one per frame value, then the composition, then
    /// each periodic claim: what the zero-knowledge rank check reads the mask
    /// columns' coefficients from.
    pub deep_coeffs: Vec<Fp2>,
}

/// Replay the prefix of the preprocessed verifier at `extra_blowup_bits`, the
/// rate the proof was made at, under the statement's `publics`, and return
/// the composition it determines.
///
/// `perm` is the second round's root when the trace was committed in two
/// rounds, and `None` when it was not. It is a parameter rather than a default
/// because the caller is the only one who knows, and the version of this that
/// assumed `None` answered for a two round artifact with a point the proof
/// never opened.
pub fn replay_comp_z_pre<A: AirExt + Permuted>(
    air: &mut A,
    pre: &StarkProofExtPre,
    perm: Option<&[u8; 32]>,
    extra_blowup_bits: u32,
    publics: &[Fp],
) -> Result<ReplayedPre, &'static str> {
    let proof = &pre.proof;
    let log_t = air.log_trace_len();
    let t = 1usize << log_t;
    let (log_n, _) = domain_params_blown(air, extra_blowup_bits);
    let n = 1usize << log_n;
    let g = root_of_unity(log_t);
    let shift = Fp::from_u64(COSET_SHIFT);

    let mut ts = Transcript::new(b"NONOS-STARK-EXT");
    let (challenges, coeffs, z) = transcript_to_z(
        &mut ts,
        &Prefix {
            publics,
            trace_root: &proof.trace_root,
            perm_root: perm,
            comp_root: &proof.comp_root,
            n_coeffs: num_coeffs(air),
            shift,
            n,
            t,
            challenge_lanes: air.challenge_lanes(),
        },
    );
    /*
     * The pair goes into the AIR before anything is evaluated over it.
     *
     * `air` is `&mut` for this and for nothing else. An assembled AIR holds the
     * constructor placeholder until something draws, and the placeholder is the
     * pair the recorded forgery was built at, so a composition computed over an
     * undrawn AIR is honest arithmetic about a circuit nobody proved. It was
     * computed that way, and the resulting lane vector and composition value
     * were handed to another lane and matched there, which proves the two
     * agree with each other and nothing about the proof.
     *
     * Setting it here rather than asking the caller to is the point: every
     * caller of this has a two round proof in one hand and an assembled AIR in
     * the other, and there is no reading of that pair where the AIR should keep
     * the placeholder.
     */
    if let Some((beta, gamma)) = challenges {
        adopt_pair(air, beta, gamma);
    }
    let comp_z = compose_ext(air, g, z, &proof.ood_frame, &pre.periodic_z, &coeffs);

    // On to the seed, in the verifier's order: the frame and the periodic
    // claims absorbed, the DEEP coefficients drawn, then the seed.
    ts.absorb_fp2_vec(&proof.ood_frame);
    ts.absorb_fp2_vec(&pre.periodic_z);
    let n_deep = air.trace_width() * air.window_size() + 1 + pre.periodic_z.len();
    // The DEEP round is replayed exactly as the verifier runs it: a nonce that
    // does not meet its grind ends the replay, so nothing downstream (the rank
    // certificate, an emitter, the outer) works from a proof that does not
    // verify.
    let mut deep_coeffs =
        draw_deep_coeffs_checked(&mut ts, n_deep, air.challenge_lanes(), pre.deep_nonce)
            .ok_or("the DEEP nonce does not meet its grind")?;
    if let Some(pair) = air.mask_pair() {
        mask_pair_coeffs(&mut deep_coeffs, air.trace_width(), air.window_size(), pair);
    }
    let seed = ts.challenge_seed();

    Ok(ReplayedPre {
        coeffs,
        z,
        comp_z,
        challenges,
        seed,
        deep_coeffs,
    })
}
