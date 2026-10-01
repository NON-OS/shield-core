// NONOS Operating System (AGPL-3.0-or-later)

//! The preprocessed poseidon verifier: the periodic root arrives as a baked
//! constant, the proof carries the claimed periodic values at z and one
//! opened periodic row per query, and DEEP holds one quotient per periodic
//! column against the claims. Nothing here recomputes the schedule, which is
//! the whole point: a recursion that replays this algorithm carries the root
//! as a constant instead of half its rows.

use super::super::field::Fp;
use super::super::fri::root_of_unity;
use super::super::fri_poseidon_ext::fri_verify_poseidon_ext_seeded;
use super::super::poseidon_merkle::{pair_at, verify_path};
use super::composition::{compose_ext, domain_params_blown};
use super::deep_identity::{batched, At, Opened};
use super::periodic_poseidon::hash_periodic_row;
use super::poseidon::{Poseidon, RATE};
use super::spec::AirExt;
use super::wire::types_poseidon_pre::StarkProofExtPPre;

/// The coset the evaluation domain sits on, from the one place that
/// defines it. The structure file publishes this value, so a private copy
/// is a second truth that stays 7 while the emit says otherwise.
use super::prove_ext::COSET_SHIFT as SHIFT;

/// Verify a sidecar proof against the baked `periodic_root`, bound to
/// `publics`. Exact transcript counterpart of `stark_prove_poseidon_pre_pub`.
#[allow(clippy::too_many_arguments)]
pub fn stark_verify_poseidon_pre_pub<A: AirExt>(
    air: &A,
    pre: &StarkProofExtPPre,
    n_queries: usize,
    grind_bits: u32,
    extra_blowup_bits: u32,
    hasher: &Poseidon,
    publics: &[Fp],
    periodic_root: &[Fp; RATE],
) -> bool {
    let proof = &pre.proof;
    let log_t = air.log_trace_len();
    let width = air.trace_width();
    let (log_n, fri_log_blowup) = domain_params_blown(air, extra_blowup_bits);
    let n = 1usize << log_n;
    let window_size = air.window_size();
    let n_periodic = air.periodic_columns().len();

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

    let r = super::replay::replay(
        air,
        proof,
        Some(&pre.periodic_z),
        None,
        extra_blowup_bits,
        hasher,
        publics,
    );
    let (coeffs, z, deep_coeffs) = (r.coeffs.clone(), r.z, r.deep_coeffs.clone());
    let comp_z = compose_ext(air, g, z, &proof.ood_frame, &pre.periodic_z, &coeffs);

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
        Some(r.seed),
    ) else {
        return false;
    };
    if positions.len() != proof.queries.len() {
        return false;
    }
    let deep_root = proof.fri.roots[0];

    for (k, (qd, po)) in proof.queries.iter().zip(&pre.openings).enumerate() {
        let p = positions[k];
        if qd.trace.len() != width || po.row.len() != n_periodic {
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
            || !verify_path(
                hasher,
                periodic_root,
                p,
                hash_periodic_row(hasher, &po.row),
                &po.path,
            )
        {
            return false;
        }

        let x = shift * omega.pow(p as u64);
        let at = At {
            z,
            g,
            x,
            width,
            window: window_size,
        };
        let opened = Opened {
            frame: &proof.ood_frame,
            trace: &qd.trace,
            comp: qd.comp,
            comp_z,
            row: &po.row,
            periodic_z: &pre.periodic_z,
        };
        if batched(&at, &deep_coeffs, &opened) != qd.deep {
            return false;
        }
    }

    true
}
