// NONOS Operating System (AGPL-3.0-or-later)

//! The deployment verifier for the preprocessed-periodic proof. It runs the
//! commitment-scheme semantics an on-chain verifier runs: authenticate each
//! query's wide periodic row against the baked `periodic_root`, and check the
//! DEEP quotient with the periodic terms folded in, so the claims at z are
//! bound by the low-degree argument instead of recomputed. Being the native
//! reference, it additionally recomputes the periodic evaluations at z and
//! requires the claims to match exactly: strictly stronger than the on-chain
//! check, so a vector this accepts is sound under either semantics. It only
//! reads the proof and never panics.

use super::super::field::{Fp, Fp2};
use super::super::fri::root_of_unity;
use super::super::fri_ext::deep_leaf;
use super::super::fri_ext::fri_verify_ext_seeded;
use super::super::merkle::{verify_path_ext, verify_path_wide, verify_path_wide_periodic};
use super::super::poly::eval_cols_on_subgroup_ext;
use super::super::transcript::Transcript;
use super::composition::{compose_ext, domain_params_blown, num_coeffs};
use super::prove_ext::draw_ood_point_ext;
use super::spec::AirExt;
use super::wire::types_ext_pre::StarkProofExtPre;
use alloc::vec::Vec;

/// The coset the evaluation domain sits on, from the one place that
/// defines it. The structure file publishes this value, so a private copy
/// is a second truth that stays 7 while the emit says otherwise.
use super::prove_ext::COSET_SHIFT as SHIFT;

/// Verify a preprocessed-periodic `proof` against `air` and the baked
/// `periodic_root`, for a statement with no public inputs. Domain sizing
/// matches the prover.
pub fn stark_verify_ext_preprocessed<A: AirExt>(
    air: &A,
    pre: &StarkProofExtPre,
    n_queries: usize,
    grind_bits: u32,
    extra_blowup_bits: u32,
    periodic_root: &[u8; 32],
) -> bool {
    stark_verify_ext_preprocessed_pub(
        air,
        pre,
        n_queries,
        grind_bits,
        extra_blowup_bits,
        periodic_root,
        &[],
    )
}

/// The same verification for a statement with public inputs. `publics` are
/// absorbed first of all, before the trace root, one field element each in
/// order, exactly as the prover absorbed them, so every challenge after
/// depends on them. A proof presented under other public inputs derives
/// other challenges and fails at its first query. A chain verifier mirrors
/// this at the session open: the words are what the checkpoint is taken
/// over, and the chunks are then checked against a transcript that already
/// contains them.
#[allow(clippy::too_many_arguments)]
pub fn stark_verify_ext_preprocessed_pub<A: AirExt>(
    air: &A,
    pre: &StarkProofExtPre,
    n_queries: usize,
    grind_bits: u32,
    extra_blowup_bits: u32,
    periodic_root: &[u8; 32],
    publics: &[Fp],
) -> bool {
    let proof = &pre.proof;
    let log_t = air.log_trace_len();
    let t = 1usize << log_t;
    let width = air.trace_width();
    let (log_n, fri_log_blowup) = domain_params_blown(air, extra_blowup_bits);
    let n = 1usize << log_n;
    let window_size = air.window_size();
    let periodic_cols = air.periodic_columns();
    let n_periodic = periodic_cols.len();

    if proof.ood_frame.len() != window_size * width
        || proof.queries.len() != n_queries
        || pre.periodic_z.len() != n_periodic
        || pre.openings.len() != n_queries
    {
        return false;
    }

    let g = root_of_unity(log_t);
    let omega = root_of_unity(log_n);
    let shift = Fp::from_u64(SHIFT);

    let mut transcript = Transcript::new(b"NONOS-STARK-EXT");
    transcript.absorb_fp_vec(publics);
    transcript.absorb_digest(&proof.trace_root);
    let coeffs: Vec<Fp2> = (0..num_coeffs(air))
        .map(|_| transcript.challenge_fp2())
        .collect();
    transcript.absorb_digest(&proof.comp_root);
    let z = draw_ood_point_ext(&mut transcript, shift, n, t);
    transcript.absorb_fp2_vec(&proof.ood_frame);
    transcript.absorb_fp2_vec(&pre.periodic_z);
    let deep_coeffs: Vec<Fp2> = (0..width * window_size + 1 + n_periodic)
        .map(|_| transcript.challenge_fp2())
        .collect();

    // Native ground truth: the claims must equal this verifier's own
    // recomputation. An on-chain verifier omits this and relies on the
    // commitment plus the DEEP argument below.
    let ours = eval_cols_on_subgroup_ext(g, t, &periodic_cols, z);
    if ours != pre.periodic_z {
        return false;
    }
    let comp_z = compose_ext(air, g, z, &proof.ood_frame, &pre.periodic_z, &coeffs);

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

    for (k, (qd, op)) in proof.queries.iter().zip(pre.openings.iter()).enumerate() {
        let p = positions[k];
        let Some(layer_zero) = proof.fri.queries.get(k).and_then(|fq| fq.layers.first()) else {
            return false;
        };
        let deep = deep_leaf::value(layer_zero, p, n);
        if qd.trace.len() != width || op.row.len() != n_periodic {
            return false;
        }
        if !verify_path_ext(&proof.comp_root, p, qd.comp, &qd.comp_path)
            || !verify_path_wide(&proof.trace_root, p, &qd.trace, &qd.trace_path)
            || !verify_path_wide_periodic(periodic_root, p, &op.row, &op.path)
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
        let inv_x_z = (Fp2::from_base(x) - z).inv();
        let e = deep_coeffs[width * window_size];
        acc = acc + e * ((qd.comp - comp_z) * inv_x_z);
        for (pi, v) in op.row.iter().enumerate() {
            let pc = deep_coeffs[width * window_size + 1 + pi];
            acc = acc + pc * ((Fp2::from_base(*v) - pre.periodic_z[pi]) * inv_x_z);
        }
        if acc != deep {
            return false;
        }
    }

    true
}
