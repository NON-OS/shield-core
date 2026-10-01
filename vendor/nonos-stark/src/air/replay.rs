// NONOS Operating System (AGPL-3.0-or-later)

//! The poseidon transcript replay, written once. Every consumer that rederives
//! the prover's challenges walked this sequence as its own copy: the deep-term
//! builders, the opening builders, the verifiers, plain and preprocessed. Five
//! copies of one walk is five places a drift can hide, and the sidecar found
//! one. The walk lives here; a consumer says whether claims ride the proof and
//! where it wants to stop.

use super::super::field::{Fp, Fp2};
use super::super::fri::root_of_unity;
use super::super::fri_poseidon_ext::fri_positions_poseidon;
use super::super::poseidon_transcript::PoseidonTranscript;
use super::composition::{domain_params_blown, num_coeffs};
use super::draw_ood_poseidon::draw_ood_point_poseidon;
use super::poseidon::{Poseidon, RATE};
use super::spec::AirExt;
use super::wire::types_poseidon_ext::StarkProofExtP;
use alloc::vec::Vec;

/// The coset the evaluation domain sits on, from the one place that
/// defines it. The structure file publishes this value, so a private copy
/// is a second truth that stays 7 while the emit says otherwise.
use super::prove_ext::COSET_SHIFT as SHIFT;

/// Everything the transcript yields up to and including the DEEP coefficients,
/// the seed it hands FRI after them, and the positions FRI draws under that
/// seed: the positions every consistency query opens at.
pub struct Replayed {
    pub coeffs: Vec<Fp2>,
    pub z: Fp2,
    pub deep_coeffs: Vec<Fp2>,
    /// FRI's seed, the extension challenge after the DEEP draw, as the two
    /// elements FRI absorbs before layer zero.
    pub seed: [Fp; 2],
    /// FRI's positions under the seed, replayed and not checked: a verifier
    /// takes them from `fri_verify_poseidon_ext_seeded`, which returns them
    /// only when FRI accepts.
    pub positions: Vec<usize>,
    pub ts: PoseidonTranscript,
}

/// Replay the prover's walk over `proof`, bound to `publics`. `claims` is the
/// periodic sidecar when the proof carries one: absorbed after the frame, and
/// the coefficient draw widens with it. `perm` is the second commitment root
/// when the trace was committed in two rounds: the challenges come out against
/// the first root and this one goes in after them. `None` for either is the
/// plain path, bit for bit the sequence it always was.
#[allow(clippy::too_many_arguments)]
pub fn replay<A: AirExt>(
    air: &A,
    proof: &StarkProofExtP,
    claims: Option<&[Fp2]>,
    perm: Option<&[Fp; RATE]>,
    extra_blowup_bits: u32,
    hasher: &Poseidon,
    publics: &[Fp],
) -> Replayed {
    let log_t = air.log_trace_len();
    let t = 1usize << log_t;
    let width = air.trace_width();
    let (log_n, _) = domain_params_blown(air, extra_blowup_bits);
    let n = 1usize << log_n;
    let window_size = air.window_size();
    let n_claims = claims.map(|c| c.len()).unwrap_or(0);

    let mut ts = PoseidonTranscript::new(hasher.clone());
    for &p in publics {
        ts.absorb(p);
    }
    ts.absorb_digest(&proof.trace_root);
    if let Some(root) = perm {
        super::compose_witness::draw_rounds_challenges(&mut ts, air.challenge_lanes());
        ts.absorb_digest(root);
    }
    let coeffs: Vec<Fp2> = ts.challenge_powers(num_coeffs(air));
    ts.absorb_digest(&proof.comp_root);
    let z = draw_ood_point_poseidon(&mut ts, Fp::from_u64(SHIFT), n, t);
    for value in &proof.ood_frame {
        ts.absorb(value.c0);
        ts.absorb(value.c1);
    }
    if let Some(cl) = claims {
        for value in cl {
            ts.absorb(value.c0);
            ts.absorb(value.c1);
        }
    }
    let deep_coeffs: Vec<Fp2> = ts.challenge_powers(width * window_size + 1 + n_claims);
    /*
     * The seed, in place of the first FRI root and the index draws this
     * transcript used to make. FRI absorbs it before its roots and draws the
     * positions after its nonce, so the consistency check is ground with FRI.
     */
    let s = ts.challenge_fp2();
    let seed = [s.c0, s.c1];
    let positions = fri_positions_poseidon(&proof.fri, log_n, hasher, Some(seed));

    Replayed {
        coeffs,
        z,
        deep_coeffs,
        seed,
        positions,
        ts,
    }
}

/// The k-th consistency index after a replay: FRI's k-th position. A query
/// past the proof's count has no position; it yields `n`, which no opening
/// can sit at, so a witness built on it fails rather than opening elsewhere.
pub fn query_index(r: &mut Replayed, n: usize, query: usize) -> usize {
    r.positions.get(query).copied().unwrap_or(n)
}

/// The evaluation domain size the replay's index draws range over.
pub fn domain_size<A: AirExt>(air: &A, extra_blowup_bits: u32) -> usize {
    1usize << domain_params_blown(air, extra_blowup_bits).0
}

/// The trace-domain generator, for consumers composing at z.
pub fn trace_generator<A: AirExt>(air: &A) -> Fp {
    root_of_unity(air.log_trace_len())
}
