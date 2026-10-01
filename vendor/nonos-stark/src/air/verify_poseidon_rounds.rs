// NONOS Operating System (AGPL-3.0-or-later)

//! Verifying a preprocessed Poseidon proof whose trace was committed in two
//! rounds. The walk is `verify_poseidon_pre`'s with two differences: the
//! permutation challenges are drawn from the first round's root and handed to
//! the AIR before anything is evaluated against it, and a query's row is
//! checked in halves, the regions under the first root and the permutation
//! columns under the second.
//!
//! A verifier that took beta and gamma from anywhere else, or that checked one
//! root against the whole row, would be back at a copy constraint argued at a
//! point its prover chose.

use super::super::field::Fp;
use super::super::fri::root_of_unity;
use super::super::fri_poseidon_ext::fri_verify_poseidon_ext_seeded;
use super::super::poseidon_merkle::{pair_at, verify_path};
use super::composition::{compose_ext, domain_params_blown};
use super::deep_identity::{batched, At, Opened};
use super::periodic_poseidon::hash_periodic_row;
use super::poseidon::{Poseidon, RATE};
use super::rounds::Permuted;
use super::spec::AirExt;
use super::wire::types_poseidon_rounds::StarkProofExtPRounds;

/// The coset the evaluation domain sits on, from the one place that
/// defines it. The structure file publishes this value, so a private copy
/// is a second truth that stays 7 while the emit says otherwise.
use super::prove_ext::COSET_SHIFT as SHIFT;

/// Verify `rounds` against `air` and the baked `periodic_root`.
///
/// `air` is taken mutably and left carrying the drawn challenges, because the
/// constraint set the composition was built from is the one at those
/// challenges. A caller that reused an AIR still holding the circuit's
/// defaults would be checking a different statement.
#[allow(clippy::too_many_arguments)]
pub fn stark_verify_poseidon_rounds<A: AirExt + Permuted>(
    air: &mut A,
    rounds: &StarkProofExtPRounds,
    n_queries: usize,
    grind_bits: u32,
    extra_blowup_bits: u32,
    hasher: &Poseidon,
    publics: &[Fp],
    periodic_root: &[Fp; RATE],
) -> bool {
    let pre = &rounds.pre;
    let proof = &pre.proof;
    let (log_t, width, window) = (air.log_trace_len(), air.trace_width(), air.window_size());
    let (log_n, fri_log_blowup) = domain_params_blown(&*air, extra_blowup_bits);
    let n = 1usize << log_n;
    let n_periodic = air.periodic_columns().len();
    let rw = rounds.region_width;

    // The split is the proof's claim and the AIR's fact. A proof that disagrees
    // is checking two roots against halves of its own choosing.
    if rw != air.region_width() || rw >= width {
        return false;
    }
    if proof.ood_frame.len() != window * width
        || proof.queries.len() != n_queries
        || pre.periodic_z.len() != n_periodic
        || pre.openings.len() != n_queries
        || rounds.perm_paths.len() != n_queries
    {
        return false;
    }

    super::compose_witness::adopt_rounds_challenges(&mut *air, hasher, publics, &proof.trace_root);

    let g = root_of_unity(log_t);
    let omega = root_of_unity(log_n);
    let shift = Fp::from_u64(SHIFT);

    let r = super::replay::replay(
        &*air,
        proof,
        Some(&pre.periodic_z),
        Some(&rounds.perm_root),
        extra_blowup_bits,
        hasher,
        publics,
    );
    let comp_z = compose_ext(&*air, g, r.z, &proof.ood_frame, &pre.periodic_z, &r.coeffs);

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

    for (k, ((qd, po), perm_path)) in proof
        .queries
        .iter()
        .zip(&pre.openings)
        .zip(&rounds.perm_paths)
        .enumerate()
    {
        let p = positions[k];
        if qd.trace.len() != width || po.row.len() != n_periodic {
            return false;
        }
        let row = hash_periodic_row(hasher, &qd.trace[..rw]);
        let perm = hash_periodic_row(hasher, &qd.trace[rw..]);
        /*
         * Both values under the fold-pair leaf they share. `pair_at` owns the
         * index rule and the order of the two, so a caller that recomputed
         * either would be a second opinion about the commitment.
         */
        let (deep_i, deep_leaf, _) = pair_at(p, n, qd.deep, qd.deep_sib);
        let (comp_i, comp_leaf, _) = pair_at(p, n, qd.comp, qd.comp_sib);
        if !verify_path(hasher, &deep_root, deep_i, deep_leaf, &qd.deep_path)
            || !verify_path(hasher, &proof.comp_root, comp_i, comp_leaf, &qd.comp_path)
            || !verify_path(hasher, &proof.trace_root, p, row, &qd.trace_path)
            || !verify_path(hasher, &rounds.perm_root, p, perm, perm_path)
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

        let at = At {
            z: r.z,
            g,
            x: shift * omega.pow(p as u64),
            width,
            window,
        };
        let opened = Opened {
            frame: &proof.ood_frame,
            trace: &qd.trace,
            comp: qd.comp,
            comp_z,
            row: &po.row,
            periodic_z: &pre.periodic_z,
        };
        if batched(&at, &r.deep_coeffs, &opened) != qd.deep {
            return false;
        }
    }

    true
}
