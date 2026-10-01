// NONOS Operating System (AGPL-3.0-or-later)

//! The money-grade DEEP STARK verifier. Same checks as the base verifier, done in
//! the extension: it evaluates the constraints once at the out-of-domain point
//! `z in Fp2`, verifies the DEEP quotient is low degree with the money-grade FRI,
//! and at each sampled position recomputes that quotient from the committed trace
//! (base leaf) and composition (extension leaf) openings. It only reads the proof
//! and never panics.

use super::super::field::{Fp, Fp2};
use super::super::fri::root_of_unity;
use super::super::fri_ext::deep_leaf;
use super::super::fri_ext::fri_verify_ext_seeded;
use super::super::merkle::{verify_path_ext, verify_path_wide};
use super::super::poly::eval_cols_on_subgroup_ext;
use super::super::transcript::Transcript;
use super::composition::{compose_ext, domain_params_blown, num_coeffs};
use super::prove_ext::draw_ood_point_ext;
use super::spec::AirExt;
use super::wire::types_ext::StarkProofExt;
use alloc::vec::Vec;

/// The coset the evaluation domain sits on, from the one place that
/// defines it. The structure file publishes this value, so a private copy
/// is a second truth that stays 7 while the emit says otherwise.
use super::prove_ext::COSET_SHIFT as SHIFT;

/// Verify a money-grade `proof` against `air`. Domain sizing matches the prover.
pub fn stark_verify_ext<A: AirExt>(
    air: &A,
    proof: &StarkProofExt,
    n_queries: usize,
    grind_bits: u32,
) -> bool {
    stark_verify_ext_blown(air, proof, n_queries, grind_bits, 0)
}

/// The same verifier, with `extra_blowup_bits` matching the prover's. A deployment
/// verifier pins this to the value the vector was proven at.
pub fn stark_verify_ext_blown<A: AirExt>(
    air: &A,
    proof: &StarkProofExt,
    n_queries: usize,
    grind_bits: u32,
    extra_blowup_bits: u32,
) -> bool {
    stark_verify_ext_blown_bound(air, proof, n_queries, grind_bits, extra_blowup_bits, &[])
}

/// The same verifier bound to `context`, absorbed into the transcript first, so a
/// proof drawn under one context never verifies under another. The money-grade
/// attestation verifier.
pub fn stark_verify_ext_blown_bound<A: AirExt>(
    air: &A,
    proof: &StarkProofExt,
    n_queries: usize,
    grind_bits: u32,
    extra_blowup_bits: u32,
    context: &[u8],
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

    let mut transcript = Transcript::new(b"NONOS-STARK-EXT");
    if !context.is_empty() {
        transcript.absorb_digest(&crate::hash::keccak256(context));
    }
    transcript.absorb_digest(&proof.trace_root);
    let coeffs: Vec<Fp2> = (0..num_coeffs(air))
        .map(|_| transcript.challenge_fp2())
        .collect();
    transcript.absorb_digest(&proof.comp_root);
    let z = draw_ood_point_ext(&mut transcript, shift, n, t);
    transcript.absorb_fp2_vec(&proof.ood_frame);
    let deep_coeffs: Vec<Fp2> = (0..width * window_size + 1)
        .map(|_| transcript.challenge_fp2())
        .collect();

    // The constraints checked once at the out-of-domain point from the claimed
    // frame, with this verifier's own composition algebra.
    let periodic_z: Vec<Fp2> = eval_cols_on_subgroup_ext(g, t, &air.periodic_columns(), z);
    let comp_z = compose_ext(air, g, z, &proof.ood_frame, &periodic_z, &coeffs);

    // The DEEP quotient polynomial must be low degree.
    /*
     * One set of positions: FRI draws them after its nonce, seeded by the
     * whole transcript above, and the consistency check runs at the same
     * ones, reading the DEEP value from FRI's own layer-zero opening. A
     * check that drew its own positions here was not ground.
     */
    let seed = transcript.challenge_seed();
    let Some(positions) = fri_verify_ext_seeded(
        &proof.fri,
        shift,
        log_n,
        fri_log_blowup,
        n_queries,
        grind_bits,
        Some(&seed),
    ) else {
        return false;
    };
    if positions.len() != proof.queries.len() {
        return false;
    }

    for (k, qd) in proof.queries.iter().enumerate() {
        let p = positions[k];
        let Some(layer_zero) = proof.fri.queries.get(k).and_then(|fq| fq.layers.first()) else {
            return false;
        };
        let deep = deep_leaf::value(layer_zero, p, n);
        if qd.trace.len() != width {
            return false;
        }
        if !verify_path_ext(&proof.comp_root, p, qd.comp, &qd.comp_path)
            || !verify_path_wide(&proof.trace_root, p, &qd.trace, &qd.trace_path)
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
        if acc != deep {
            return false;
        }
    }

    true
}
