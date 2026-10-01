// NONOS Operating System (AGPL-3.0-or-later)

//! Extracting the out-of-domain composition inputs of a Poseidon-committed proof:
//! the out-of-domain frame is the proof's, and the batching coefficients, the
//! out-of-domain point, and the periodic columns at that point are recovered by
//! replaying the transcript exactly as the verifier does. These are the inputs a
//! recursive verifier feeds to an in-circuit `compose_ext`, so it can prove the
//! composition value the DEEP check consumes was honestly formed.

use super::super::air::Poseidon;
use super::poseidon::RATE;
use super::super::field::{Fp, Fp2};
use super::super::fri::root_of_unity;
use super::super::poly::eval_cols_on_subgroup_ext;
use super::super::poseidon_transcript::PoseidonTranscript;
use super::composition::{compose_ext, domain_params_blown, num_coeffs};
use super::draw_ood_poseidon::draw_ood_point_poseidon;
use super::spec::AirExt;
use super::wire::types_poseidon_ext::StarkProofExtP;
use alloc::vec::Vec;

/// The coset the evaluation domain sits on, from the one place that
/// defines it. The structure file publishes this value, so a private copy
/// is a second truth that stays 7 while the emit says otherwise.
use super::prove_ext::COSET_SHIFT as SHIFT;

/// The composition inputs at the out-of-domain point: the batching coefficients,
/// the periodic columns evaluated at `z`, the point `z`, and the resulting
/// composition value. The out-of-domain frame is `proof.ood_frame` directly.
pub struct ComposeInputs {
    pub coeffs: Vec<Fp2>,
    pub periodic_z: Vec<Fp2>,
    pub z: Fp2,
    pub comp_z: Fp2,
}

/// Replay the transcript up to the out-of-domain challenges and assemble the
/// composition inputs of `proof` under `air`.
pub fn compose_inputs<A: AirExt>(
    air: &A,
    proof: &StarkProofExtP,
    extra_blowup_bits: u32,
    hasher: &Poseidon,
) -> ComposeInputs {
    compose_inputs_pub(air, proof, extra_blowup_bits, hasher, &[])
}

/// The transcript up to the out-of-domain point: the batching coefficients and
/// `z`. `perm` is the two round inner's second commitment root, which the
/// transcript takes in between the challenges it draws from the first root and
/// the coefficients. A one round proof passes none and the walk is the shorter
/// one; passing the wrong one moves every draw after it, which is the whole
/// point of drawing them there.
#[allow(clippy::too_many_arguments)]
fn replay<A: AirExt>(
    air: &A,
    proof: &StarkProofExtP,
    hasher: &Poseidon,
    publics: &[Fp],
    perm: Option<&[Fp; RATE]>,
    shift: Fp,
    n: usize,
    t: usize,
) -> (Vec<Fp2>, Fp2) {
    let mut ts = PoseidonTranscript::new(hasher.clone());
    for &p in publics {
        ts.absorb(p);
    }
    ts.absorb_digest(&proof.trace_root);
    if let Some(root) = perm {
        draw_rounds_challenges(&mut ts, air.challenge_lanes());
        ts.absorb_digest(root);
    }
    let coeffs: Vec<Fp2> = ts.challenge_powers(num_coeffs(air));
    ts.absorb_digest(&proof.comp_root);
    let z = draw_ood_point_poseidon(&mut ts, shift, n, t);
    (coeffs, z)
}

/// The same extraction, replaying `publics` into the transcript first, matching a
/// proof produced with `stark_prove_poseidon_ext_pub`.
pub fn compose_inputs_pub<A: AirExt>(
    air: &A,
    proof: &StarkProofExtP,
    extra_blowup_bits: u32,
    hasher: &Poseidon,
    publics: &[Fp],
) -> ComposeInputs {
    let log_t = air.log_trace_len();
    let t = 1usize << log_t;
    let (log_n, _) = domain_params_blown(air, extra_blowup_bits);
    let n = 1usize << log_n;

    let g = root_of_unity(log_t);
    let shift = Fp::from_u64(SHIFT);

    let (coeffs, z) = replay(air, proof, hasher, publics, None, shift, n, t);

    let periodic_z: Vec<Fp2> = eval_cols_on_subgroup_ext(g, t, &air.periodic_columns(), z);
    let comp_z = compose_ext(air, g, z, &proof.ood_frame, &periodic_z, &coeffs);

    ComposeInputs {
        coeffs,
        periodic_z,
        z,
        comp_z,
    }
}

/// The compose inputs of a preprocessed proof: identical replay up to z, then
/// the claims are the periodic values, no recompute anywhere. The draws before
/// z do not depend on what follows, so the plain replay serves both forms.
pub fn compose_inputs_pre<A: AirExt>(
    air: &A,
    pre: &super::wire::types_poseidon_pre::StarkProofExtPPre,
    extra_blowup_bits: u32,
    hasher: &Poseidon,
    publics: &[Fp],
) -> ComposeInputs {
    let mut ci = compose_inputs_pub(air, &pre.proof, extra_blowup_bits, hasher, publics);
    ci.periodic_z = pre.periodic_z.clone();
    ci.comp_z = compose_ext(
        air,
        root_of_unity(air.log_trace_len()),
        ci.z,
        &pre.proof.ood_frame,
        &ci.periodic_z,
        &ci.coeffs,
    );
    ci
}

/// The permutation challenges a two round proof drew, from the same replay the
/// verifier runs: the publics, then the first round's root, then two squeezes.
///
/// A caller that rebuilds the AIR rather than keeping the one the prover handed
/// back needs these to put it back in the state the proof was made against.
pub fn rounds_challenges(hasher: &Poseidon, publics: &[Fp], trace_root: &[Fp; RATE]) -> (Fp, Fp) {
    let mut ts = PoseidonTranscript::new(hasher.clone());
    for &p in publics {
        ts.absorb(p);
    }
    ts.absorb_digest(trace_root);
    (ts.challenge(), ts.challenge())
}

/// Beta then gamma off `ts`, in `Fp` or `Fp2` as the AIR's
/// `challenge_lanes` says. The prover, the verifier's replay and the recursion's
/// transcript all draw through this rule, so the three cannot disagree about
/// how many lanes a challenge reads.
pub fn draw_rounds_challenges(ts: &mut PoseidonTranscript, lanes: usize) -> (Fp2, Fp2) {
    if lanes == 2 {
        (ts.challenge_fp2(), ts.challenge_fp2())
    } else {
        (Fp2::from_base(ts.challenge()), Fp2::from_base(ts.challenge()))
    }
}

/// Put `air` in the state a two round Poseidon proof over `trace_root` was
/// made in: replay to the challenges, draw them at the AIR's width, adopt them.
/// A caller that rebuilds the AIR rather than keeping the prover's copy needs
/// this before it evaluates a single constraint.
pub fn adopt_rounds_challenges<A: AirExt + super::rounds::Permuted>(
    air: &mut A,
    hasher: &Poseidon,
    publics: &[Fp],
    trace_root: &[Fp; RATE],
) {
    let mut ts = PoseidonTranscript::new(hasher.clone());
    for &p in publics {
        ts.absorb(p);
    }
    ts.absorb_digest(trace_root);
    let (beta, gamma) = draw_rounds_challenges(&mut ts, air.challenge_lanes());
    if air.challenge_lanes() == 2 {
        air.set_challenges_ext(beta, gamma);
    } else {
        air.set_challenges(beta.c0, gamma.c0);
    }
}

/// The compose inputs of a two round preprocessed proof.
///
/// The claims are the proof's, as in the one round form; what differs is the
/// replay, which takes in the permutation root where the prover put it. `air`
/// must already carry the drawn challenges, because the composition value here
/// is the one the proof's own constraints produce and those constraints are the
/// ones at that pair.
pub fn compose_inputs_pre_rounds<A: AirExt>(
    air: &A,
    rounds: &super::wire::types_poseidon_rounds::StarkProofExtPRounds,
    extra_blowup_bits: u32,
    hasher: &Poseidon,
    publics: &[Fp],
) -> ComposeInputs {
    let pre = &rounds.pre;
    let log_t = air.log_trace_len();
    let t = 1usize << log_t;
    let (log_n, _) = domain_params_blown(air, extra_blowup_bits);
    let (coeffs, z) = replay(
        air,
        &pre.proof,
        hasher,
        publics,
        Some(&rounds.perm_root),
        Fp::from_u64(SHIFT),
        1usize << log_n,
        t,
    );
    let g = root_of_unity(log_t);
    let periodic_z = pre.periodic_z.clone();
    let comp_z = compose_ext(air, g, z, &pre.proof.ood_frame, &periodic_z, &coeffs);
    ComposeInputs {
        coeffs,
        periodic_z,
        z,
        comp_z,
    }
}
