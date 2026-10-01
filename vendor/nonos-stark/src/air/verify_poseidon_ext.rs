// NONOS Operating System (AGPL-3.0-or-later)

//! The Poseidon-committed money-grade STARK verifier: the exact algorithm of
//! `verify_ext`, but replaying the Poseidon transcript and checking Poseidon Merkle
//! openings. It is the algorithm a recursive verifier arithmetizes, so a proof that
//! verifies here is the proof a recursion attests to.

use super::super::air::Poseidon;
use super::super::field::{Fp, Fp2};
use super::super::fri::root_of_unity;
use super::super::fri_poseidon_ext::fri_verify_poseidon_ext_seeded;
use super::super::poly::eval_cols_on_subgroup_ext;
use super::super::poseidon_merkle::{pair_at, verify_path};
use super::super::poseidon_transcript::PoseidonTranscript;
use super::composition::{compose_ext, domain_params_blown, num_coeffs};
use super::draw_ood_poseidon::draw_ood_point_poseidon;
use super::periodic_poseidon::hash_periodic_row;
use super::spec::AirExt;
use super::wire::types_poseidon_ext::StarkProofExtP;
use alloc::vec::Vec;

/// The coset the evaluation domain sits on, from the one place that
/// defines it. The structure file publishes this value, so a private copy
/// is a second truth that stays 7 while the emit says otherwise.
use super::prove_ext::COSET_SHIFT as SHIFT;

pub fn stark_verify_poseidon_ext<A: AirExt>(
    air: &A,
    proof: &StarkProofExtP,
    n_queries: usize,
    grind_bits: u32,
    extra_blowup_bits: u32,
    hasher: &Poseidon,
) -> bool {
    stark_verify_poseidon_ext_pub(
        air,
        proof,
        n_queries,
        grind_bits,
        extra_blowup_bits,
        hasher,
        &[],
    )
}

/// The same verifier, seeding the transcript with `publics` before the trace roots
/// so acceptance is bound to those public inputs by Fiat-Shamir. It is the exact
/// counterpart of `stark_prove_poseidon_ext_pub`: replaying the same seed in the
/// same order. A recursive verifier exposes `publics` in its transcript column, so
/// this is the algorithm a recursion over a public-bound proof arithmetizes.
#[allow(clippy::too_many_arguments)]
pub fn stark_verify_poseidon_ext_pub<A: AirExt>(
    air: &A,
    proof: &StarkProofExtP,
    n_queries: usize,
    grind_bits: u32,
    extra_blowup_bits: u32,
    hasher: &Poseidon,
    publics: &[Fp],
) -> bool {
    let log_t = air.log_trace_len();
    let t = 1usize << log_t;
    let width = air.trace_width();
    let (log_n, fri_log_blowup) = domain_params_blown(air, extra_blowup_bits);
    let n = 1usize << log_n;
    let window_size = air.window_size();

    if proof.ood_frame.len() != window_size * width || proof.queries.len() != n_queries {
        return false;
    }

    let g = root_of_unity(log_t);
    let omega = root_of_unity(log_n);
    let shift = Fp::from_u64(SHIFT);

    let mut transcript = PoseidonTranscript::new(hasher.clone());
    for &p in publics {
        transcript.absorb(p);
    }
    transcript.absorb_digest(&proof.trace_root);
    let coeffs: Vec<Fp2> = transcript.challenge_powers(num_coeffs(air));
    transcript.absorb_digest(&proof.comp_root);
    let z = draw_ood_point_poseidon(&mut transcript, shift, n, t);
    for value in &proof.ood_frame {
        transcript.absorb(value.c0);
        transcript.absorb(value.c1);
    }
    let deep_coeffs: Vec<Fp2> = transcript.challenge_powers(width * window_size + 1);
    let s = transcript.challenge_fp2();
    let seed = [s.c0, s.c1];

    let periodic_z: Vec<Fp2> = eval_cols_on_subgroup_ext(g, t, &air.periodic_columns(), z);
    let comp_z = compose_ext(air, g, z, &proof.ood_frame, &periodic_z, &coeffs);

    /*
     * One set of positions: FRI draws them after its nonce under the seed the
     * transcript hands it, and the consistency queries open at the same ones,
     * so the consistency check is ground with FRI.
     */
    let Some(positions) = fri_verify_poseidon_ext_seeded(
        &proof.fri,
        shift,
        log_n,
        fri_log_blowup,
        n_queries,
        grind_bits,
        hasher,
        Some(seed),
    ) else {
        return false;
    };
    if positions.len() != proof.queries.len() {
        return false;
    }
    let deep_root = proof.fri.roots[0];

    for (k, qd) in proof.queries.iter().enumerate() {
        let p = positions[k];
        if qd.trace.len() != width {
            return false;
        }
        /*
         * Both values under the fold-pair leaf they share. `pair_at` owns the
         * index rule and the order of the two, so a caller that recomputed
         * either would be a second opinion about the commitment.
         */
        let (deep_i, deep_leaf, _) = pair_at(p, n, qd.deep, qd.deep_sib);
        let (comp_i, comp_leaf, _) = pair_at(p, n, qd.comp, qd.comp_sib);
        if !verify_path(hasher, &deep_root, deep_i, deep_leaf, &qd.deep_path)
            || !verify_path(hasher, &proof.comp_root, comp_i, comp_leaf, &qd.comp_path)
            || !verify_path(
                hasher,
                &proof.trace_root,
                p,
                hash_periodic_row(hasher, &qd.trace),
                &qd.trace_path,
            )
        {
            return false;
        }

        let x = shift * omega.pow(p as u64);
        let mut acc = Fp2::ZERO;
        for k in 0..window_size {
            let zk = z * Fp2::from_base(g.pow(k as u64));
            let inv_x_zk = (Fp2::from_base(x) - zk).inv();
            for c in 0..width {
                let claimed = proof.ood_frame[k * width + c];
                acc = acc
                    + deep_coeffs[k * width + c]
                        * ((Fp2::from_base(qd.trace[c]) - claimed) * inv_x_zk);
            }
        }
        let e = deep_coeffs[width * window_size];
        acc = acc + e * ((qd.comp - comp_z) * (Fp2::from_base(x) - z).inv());
        if acc != qd.deep {
            return false;
        }
    }

    true
}
