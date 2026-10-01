// NONOS Operating System (AGPL-3.0-or-later)
//! Verifying a proof whose trace was committed in two rounds.
//!
//! The walk is the preprocessed verifier's, with two differences. The
//! permutation challenges are drawn from the first round's root and handed to
//! the AIR before anything is evaluated against it, and a query's row is
//! checked in halves, the regions under the first root and the permutation
//! columns under the second.
//!
//! Only these two things carry the soundness the fixed challenge form did not
//! have. A verifier that took beta and gamma from anywhere else, or that
//! checked one root against the whole row, would be back where it started.

use super::super::field::{Fp, Fp2};
use super::super::fri::root_of_unity;
use super::super::fri_ext::deep_leaf;
use super::super::fri_ext::{fri_positions_ext, fri_verify_ext_seeded_ground};
use super::super::merkle::{verify_path_ext, verify_path_wide, verify_path_wide_periodic};
use super::super::transcript::Transcript;
use super::composition::{compose_ext, domain_params_blown, num_coeffs};
use super::rounds::Permuted;
use super::shared_paths::{fill, SharedPaths};
use super::spec::AirExt;
use super::wire::types_ext_rounds::StarkProofExtRounds;
use alloc::vec::Vec;

/// The coset the evaluation domain sits on, from the one place that
/// defines it. The structure file publishes this value, so a private copy
/// is a second truth that stays 7 while the emit says otherwise.
use super::prove_ext::COSET_SHIFT as SHIFT;

/// Verify `rounds` against `air` and the baked `periodic_root`.
///
/// `air` is taken by value and mutated with the drawn challenges, because the
/// constraint set the composition was built from is the one at those
/// challenges. A caller that reused an AIR carrying the circuit's defaults
/// would be checking a different statement.
#[allow(clippy::too_many_arguments)]
pub fn stark_verify_ext_rounds<A: AirExt + Permuted>(
    air: A,
    rounds: &StarkProofExtRounds,
    n_queries: usize,
    grind_bits: u32,
    extra_blowup_bits: u32,
    periodic_root: &[u8; 32],
    publics: &[Fp],
) -> bool {
    stark_verify_ext_rounds_why(
        air,
        rounds,
        n_queries,
        grind_bits,
        extra_blowup_bits,
        periodic_root,
        publics,
    )
    .is_ok()
}

/// The same verification, naming the check that refused. A prover that
/// fails its own verification wants the name, not the bit.
#[allow(clippy::too_many_arguments)]
pub fn stark_verify_ext_rounds_why<A: AirExt + Permuted>(
    air: A,
    rounds: &StarkProofExtRounds,
    n_queries: usize,
    grind_bits: u32,
    extra_blowup_bits: u32,
    periodic_root: &[u8; 32],
    publics: &[Fp],
) -> Result<(), &'static str> {
    verify_rounds(
        air,
        rounds,
        None,
        n_queries,
        grind_bits,
        extra_blowup_bits,
        periodic_root,
        publics,
    )
    .map(|_| ())
}

/// The same verification, returning the positions it checked, in draw order.
/// What a prover needs to share the paths of the proof it has just verified:
/// the positions are the transcript's, and this is where the transcript is.
#[allow(clippy::too_many_arguments)]
pub fn stark_verify_ext_rounds_positions<A: AirExt + Permuted>(
    air: A,
    rounds: &StarkProofExtRounds,
    n_queries: usize,
    grind_bits: u32,
    extra_blowup_bits: u32,
    periodic_root: &[u8; 32],
    publics: &[Fp],
) -> Result<Vec<usize>, &'static str> {
    verify_rounds(
        air,
        rounds,
        None,
        n_queries,
        grind_bits,
        extra_blowup_bits,
        periodic_root,
        publics,
    )
}

/// Verify a proof whose paths travel shared (format 6). `skeleton` is the
/// proof with its paths absent; they are rebuilt from `shared` at the
/// positions this verifier draws, and then walked exactly as a per query proof
/// is. One verifier, not two: everything but the rebuild is the same code.
#[allow(clippy::too_many_arguments)]
pub fn stark_verify_ext_rounds_shared_why<A: AirExt + Permuted>(
    air: A,
    skeleton: &StarkProofExtRounds,
    shared: &SharedPaths,
    n_queries: usize,
    grind_bits: u32,
    extra_blowup_bits: u32,
    periodic_root: &[u8; 32],
    publics: &[Fp],
) -> Result<(), &'static str> {
    verify_rounds(
        air,
        skeleton,
        Some(shared),
        n_queries,
        grind_bits,
        extra_blowup_bits,
        periodic_root,
        publics,
    )
    .map(|_| ())
}

#[allow(clippy::too_many_arguments)]
fn verify_rounds<A: AirExt + Permuted>(
    mut air: A,
    rounds: &StarkProofExtRounds,
    shared: Option<&SharedPaths>,
    n_queries: usize,
    grind_bits: u32,
    extra_blowup_bits: u32,
    periodic_root: &[u8; 32],
    publics: &[Fp],
) -> Result<Vec<usize>, &'static str> {
    let pre = &rounds.pre;
    let proof = &pre.proof;
    let log_t = air.log_trace_len();
    let t = 1usize << log_t;
    let width = air.trace_width();
    let rw = rounds.region_width;
    let (log_n, fri_log_blowup) = domain_params_blown(&air, extra_blowup_bits);
    let n = 1usize << log_n;
    let window_size = air.window_size();
    let n_periodic = air.periodic_count();

    /*
     * The split is the proof's claim and the AIR's fact, and a proof that
     * disagrees about it is checking two roots against halves of its own
     * choosing.
     */
    if rw != air.region_width() || rw >= width {
        return Err("the region split is not the AIR's");
    }
    if proof.ood_frame.len() != window_size * width
        || proof.queries.len() != n_queries
        || pre.periodic_z.len() != n_periodic
        || pre.openings.len() != n_queries
        || rounds.perm_paths.len() != n_queries
    {
        return Err("the proof's counts are not the AIR's shape");
    }
    let mask_pair = air.mask_pair();
    if let Some(pair) = mask_pair {
        if !super::replay_pre::mask_pair_canonical(&proof.ood_frame, width, window_size, pair) {
            return Err("the mask pair's second frame slot is not zero");
        }
    }

    let g = root_of_unity(log_t);
    let omega = root_of_unity(log_n);
    let shift = Fp::from_u64(SHIFT);

    let mut transcript = Transcript::new(b"NONOS-STARK-EXT");
    // One order, one implementation. `replay_pre` had a copy of this and it
    // drifted into answering for a shape it was not given.
    let (challenges, coeffs, z) = super::replay_pre::transcript_to_z(
        &mut transcript,
        &super::replay_pre::Prefix {
            publics,
            trace_root: &proof.trace_root,
            perm_root: Some(&rounds.perm_root),
            comp_root: &proof.comp_root,
            n_coeffs: num_coeffs(&air),
            shift,
            n,
            t,
            challenge_lanes: air.challenge_lanes(),
        },
    );
    let (beta, gamma) = challenges.expect("a two round verify draws its challenges");
    super::replay_pre::adopt_pair(&mut air, beta, gamma);
    transcript.absorb_fp2_vec(&proof.ood_frame);
    transcript.absorb_fp2_vec(&pre.periodic_z);
    let mut deep_coeffs = super::replay_pre::draw_deep_coeffs_checked(
        &mut transcript,
        width * window_size + 1 + n_periodic,
        air.challenge_lanes(),
        pre.deep_nonce,
    )
    .ok_or("the DEEP nonce does not meet its grind")?;
    if let Some(pair) = mask_pair {
        super::replay_pre::mask_pair_coeffs(&mut deep_coeffs, width, window_size, pair);
    }

    /*
     * An AIR that has its columns checks the claims against them too. One
     * read from a program image has only their count, and its claims are held
     * by the DEEP check below, each column opened against the pinned periodic
     * root at every query (`AirExt::periodic_at`).
     */
    if let Some(ours) = air.periodic_at(g, t, z) {
        if ours != pre.periodic_z {
            return Err("the periodic claims at z are not the columns'");
        }
    }
    let comp_z = compose_ext(&air, g, z, &proof.ood_frame, &pre.periodic_z, &coeffs);

    /*
     * One set of positions: FRI draws them after its nonce, seeded by the
     * whole transcript above, and the consistency check runs at the same
     * ones, reading the DEEP value from FRI's own layer-zero opening. A
     * check that drew its own positions here was not ground.
     */
    let seed = transcript.challenge_seed();

    /*
     * Shared paths are rebuilt here, at positions replayed from the seed just
     * drawn, before anything walks a path. The replay checks no nonce; the
     * FRI below does, and draws the same positions from the same transcript,
     * which is checked rather than assumed.
     */
    let filled;
    let (rounds, replayed) = match shared {
        None => (rounds, None),
        Some(sh) => {
            let at = fri_positions_ext(&rounds.pre.proof.fri, log_n, Some(&seed));
            filled = fill(rounds, sh, &at, log_n).ok_or("a shared path stream refused")?;
            (&filled, Some(at))
        }
    };
    let pre = &rounds.pre;
    let proof = &pre.proof;

    let Some(positions) = fri_verify_ext_seeded_ground(
        &proof.fri,
        shift,
        log_n,
        fri_log_blowup,
        n_queries,
        grind_bits,
        super::replay_pre::commit_grind_bits(air.challenge_lanes()),
        super::replay_pre::grind_chunks(air.challenge_lanes()),
        Some(&seed),
    ) else {
        return Err("the FRI refused");
    };
    if positions.len() != proof.queries.len() {
        return Err("the FRI refused");
    }
    if replayed.is_some_and(|at| at != positions) {
        return Err("the shared paths were filled at other positions");
    }

    for (k, ((qd, op), perm_path)) in proof
        .queries
        .iter()
        .zip(pre.openings.iter())
        .zip(rounds.perm_paths.iter())
        .enumerate()
    {
        let p = positions[k];
        let Some(layer_zero) = proof.fri.queries.get(k).and_then(|fq| fq.layers.first()) else {
            return Err("the FRI proof has no layer zero");
        };
        let deep = deep_leaf::value(layer_zero, p, n);
        if qd.trace.len() != width || op.row.len() != n_periodic {
            return Err("a query's row lengths are not the shape");
        }
        if !verify_path_ext(&proof.comp_root, p, qd.comp, &qd.comp_path)
            || !verify_path_wide(&proof.trace_root, p, &qd.trace[..rw], &qd.trace_path)
            || !verify_path_wide(&rounds.perm_root, p, &qd.trace[rw..], perm_path)
            || !verify_path_wide_periodic(periodic_root, p, &op.row, &op.path)
        {
            return Err("a Merkle path refused");
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
            return Err("a query's DEEP value is not the combination");
        }
    }

    Ok(positions)
}
