// NONOS Operating System (AGPL-3.0-or-later)
//! Region 0: the STARK transcript in witness form, the whole of it. Publics
//! first, then the proof's own sequence through the two alphas, the
//! out-of-domain point, the frame, the claims and the seed it hands FRI, so
//! each challenge the other regions consume exists as a bindable squeeze
//! cell and each absorbed value as a bindable inject cell.
//!
//! It ends at the seed. It used to go on to absorb the first FRI root and
//! draw every consistency index itself, before any proof of work, so a
//! prover could re-roll those positions for the price of one re-blinded
//! commitment. The consistency queries now open at FRI's positions, drawn in
//! FRI's transcript after its nonce under this seed.

use super::inner::{Inner, LOG_ROUNDS};
use super::sponge::{OpCell, Recorder};
use crate::crypto::stark::air::{domain_params_blown, AirExt, Poseidon, TranscriptCheck, COSET_SHIFT, RATE};
use crate::crypto::stark::field::{Fp, Fp2};
use alloc::vec::Vec;

pub struct StarkTranscript {
    pub region: TranscriptCheck,
    pub trace: Vec<Fp>,
    /// The cells the inner's public words were absorbed from, in word order.
    pub publics: Vec<OpCell>,
    /// Where the roots were absorbed, lane by lane.
    pub trace_root: [OpCell; RATE],
    /// The second round's root, when the inner drew challenges; beta is the
    /// operation `beta_op` and gamma the next.
    pub perm_root: Option<[OpCell; RATE]>,
    pub beta_op: Option<usize>,
    /// The operation reading the alpha the composition coefficients are
    /// powers of, and that alpha.
    pub coeff_op: usize,
    pub alpha: Fp2,
    pub comp_root: [OpCell; RATE],
    /// The operation reading z, both lanes.
    pub z_op: usize,
    /// The frame's absorbed lanes, `c0` then `c1` per value.
    pub frame: Vec<OpCell>,
    /// The periodic claims' absorbed lanes, empty off the sidecar path.
    pub claims: Vec<OpCell>,
    pub deep_coeff_op: usize,
    pub deep_alpha: Fp2,
    /// The operation reading FRI's seed, both lanes, and the seed: FRI's
    /// transcript absorbs its two lanes before layer zero.
    pub seed_op: usize,
    pub seed: Fp2,
}

pub fn stark_transcript<A: AirExt>(h: &Poseidon, inner: &Inner<A>) -> StarkTranscript {
    let (log_n, _) = domain_params_blown(&inner.air, inner.extra);
    let n = 1usize << log_n;
    let t = inner.t as usize;
    let shift = Fp::from_u64(COSET_SHIFT);
    let mut r = Recorder::new(h);
    // Kept: the program-form compose region reads the public words from these
    // cells, and the assembly pins them to the outer's own public inputs.
    let publics: Vec<OpCell> = inner.publics.iter().map(|&p| r.absorb(p)).collect();
    let trace_root = r.absorb_digest(&inner.proof.trace_root);
    // A two round inner draws beta and gamma here, against the region root
    // alone, and absorbs the permutation root after. Each is one squeeze,
    // reading one lane or two as the inner's `challenge_lanes` says, the rule
    // `draw_rounds_challenges` holds the prover and the verifier to.
    let (beta_op, perm_root) = match inner.rounds.as_ref() {
        Some(rd) => {
            let b = if inner.air.challenge_lanes() == 2 {
                let (b, _) = r.challenge_fp2();
                r.challenge_fp2();
                b
            } else {
                let (b, _) = r.challenge();
                r.challenge();
                b
            };
            (Some(b), Some(r.absorb_digest(&rd.perm_root)))
        }
        None => (None, None),
    };
    let (coeff_op, alpha) = r.challenge_fp2();
    let comp_root = r.absorb_digest(&inner.proof.comp_root);
    let (z_op, _z) = r.ood_point(shift, n, t);
    let mut frame = Vec::with_capacity(2 * inner.proof.ood_frame.len());
    for value in &inner.proof.ood_frame {
        frame.push(r.absorb(value.c0));
        frame.push(r.absorb(value.c1));
    }
    // A preprocessed inner absorbs its periodic claims here; the plain path
    // absorbs nothing.
    let mut claims = Vec::new();
    if let Some(sc) = &inner.sidecar {
        for value in &sc.periodic_z {
            claims.push(r.absorb(value.c0));
            claims.push(r.absorb(value.c1));
        }
    }
    let (deep_coeff_op, deep_alpha) = r.challenge_fp2();
    let (seed_op, seed) = r.challenge_fp2();
    let region = TranscriptCheck::new_witness(h.clone(), LOG_ROUNDS, r.finish());
    let trace = region.trace();
    StarkTranscript {
        region,
        trace,
        publics,
        trace_root,
        perm_root,
        beta_op,
        coeff_op,
        alpha,
        comp_root,
        z_op,
        frame,
        claims,
        deep_coeff_op,
        deep_alpha,
        seed_op,
        seed,
    }
}
