// NONOS Operating System (AGPL-3.0-or-later)

//! The keccak transcript replay, written once: the challenge sequence of
//! `stark_verify_ext`, yielded as values instead of consumed inline, for any
//! consumer that must rederive what the prover drew. The walk certifies
//! itself: it recomputes every query's DEEP value from its own challenges, so
//! a drifted copy cannot yield a plausible fixture. An independent verifier
//! porting the transcript anchors its known-answer tests here.

use super::super::field::{Fp, Fp2};
use super::super::fri::root_of_unity;
use super::super::fri_ext::{deep_leaf, fri_positions_ext};
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

pub struct ReplayedExt {
    pub coeffs: Vec<Fp2>,
    pub z: Fp2,
    pub comp_z: Fp2,
    /// The periodic columns evaluated at z, in periodic-column order: the
    /// values the verifier computed on the way to `comp_z`, carried out so a
    /// ported composition consumes them instead of recomputing the columns.
    pub periodic_z: Vec<Fp2>,
    /// Every transition constraint evaluated at z from the claimed frame, in
    /// constraint order: the summands behind `comp_z`'s transition half, so a
    /// ported evaluator that misses is told which constraint disagrees.
    pub transitions_z: Vec<Fp2>,
    pub deep_coeffs: Vec<Fp2>,
    /// The consistency index of every query, in draw order: FRI's positions.
    pub indices: Vec<usize>,
    /// Every query's DEEP value recomputed from the challenges above equals
    /// the proof's. False means this walk does not describe this proof.
    pub deep_consistent: bool,
}

pub fn replay_challenges_ext<A: AirExt>(
    air: &A,
    proof: &StarkProofExt,
    n_queries: usize,
) -> ReplayedExt {
    let log_t = air.log_trace_len();
    let t = 1usize << log_t;
    let width = air.trace_width();
    let (log_n, _) = domain_params_blown(air, 0);
    let n = 1usize << log_n;
    let window_size = air.window_size();
    let g = root_of_unity(log_t);
    let omega = root_of_unity(log_n);
    let shift = Fp::from_u64(SHIFT);

    let mut ts = Transcript::new(b"NONOS-STARK-EXT");
    ts.absorb_digest(&proof.trace_root);
    let coeffs: Vec<Fp2> = (0..num_coeffs(air)).map(|_| ts.challenge_fp2()).collect();
    ts.absorb_digest(&proof.comp_root);
    let z = draw_ood_point_ext(&mut ts, shift, n, t);
    ts.absorb_fp2_vec(&proof.ood_frame);
    let deep_coeffs: Vec<Fp2> = (0..width * window_size + 1)
        .map(|_| ts.challenge_fp2())
        .collect();

    let periodic_z: Vec<Fp2> = eval_cols_on_subgroup_ext(g, t, &air.periodic_columns(), z);
    let comp_z = compose_ext(air, g, z, &proof.ood_frame, &periodic_z, &coeffs);
    let transitions_z = air.transition_ext(&proof.ood_frame, &periodic_z);
    // FRI's positions under the seed the transcript hands it, the ones the
    // consistency check runs at.
    let seed = ts.challenge_seed();
    let positions = fri_positions_ext(&proof.fri, log_n, Some(&seed));

    let mut indices = Vec::with_capacity(n_queries);
    let mut deep_consistent = proof.fri.queries.len() >= proof.queries.len().min(n_queries);
    for (k, qd) in proof.queries.iter().take(n_queries).enumerate() {
        let Some(&p) = positions.get(k) else {
            deep_consistent = false;
            break;
        };
        indices.push(p);
        let deep = match proof.fri.queries[k].layers.first() {
            Some(l0) => deep_leaf::value(l0, p, n),
            None => {
                deep_consistent = false;
                break;
            }
        };
        let x = Fp2::from_base(shift * omega.pow(p as u64));
        let mut acc = Fp2::ZERO;
        for k in 0..window_size {
            let zk = z * Fp2::from_base(g.pow(k as u64));
            let inv_x_zk = (x - zk).inv();
            for c in 0..width {
                let claimed = proof.ood_frame[k * width + c];
                acc = acc
                    + deep_coeffs[k * width + c]
                        * ((Fp2::from_base(qd.trace[c]) - claimed) * inv_x_zk);
            }
        }
        let e = deep_coeffs[width * window_size];
        acc = acc + e * ((qd.comp - comp_z) * (x - z).inv());
        deep_consistent &= acc == deep;
    }

    ReplayedExt {
        coeffs,
        z,
        comp_z,
        periodic_z,
        transitions_z,
        deep_coeffs,
        indices,
        deep_consistent,
    }
}
