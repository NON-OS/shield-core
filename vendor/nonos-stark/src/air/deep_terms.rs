// NONOS Operating System (AGPL-3.0-or-later)

//! Extracting the DEEP-consistency witness of a Poseidon-committed proof's query
//! `k`: replay the transcript exactly as the verifier does, recover the
//! out-of-domain point, the batching coefficients, and the k-th consistency query
//! position, then assemble the per-term data (opened value, out-of-domain claim,
//! point, coefficient) a recursive verifier feeds to `DeepCheckExt`. Query 0 is
//! the first draw; closing inner-query coverage replays every k in `0..n_queries`.

use super::super::fri_poseidon_ext::fri_positions_poseidon;
use super::super::air::Poseidon;
use super::super::field::{Fp, Fp2};
use super::super::fri::root_of_unity;
use super::super::poly::eval_cols_on_subgroup_ext;
use super::super::poseidon_transcript::PoseidonTranscript;
use super::composition::{compose_ext, domain_params_blown, num_coeffs};
use super::deep_check_ext::DeepTerm;
use super::draw_ood_poseidon::draw_ood_point_poseidon;
use super::spec::AirExt;
use super::wire::types_poseidon_ext::StarkProofExtP;
use alloc::vec::Vec;

/// The coset the evaluation domain sits on, from the one place that
/// defines it. The structure file publishes this value, so a private copy
/// is a second truth that stays 7 while the emit says otherwise.
use super::prove_ext::COSET_SHIFT as SHIFT;

/// The DEEP terms of `proof`'s first query, its evaluation point, and the query's
/// DEEP value. The transcript replay mirrors `stark_verify_poseidon_ext` up to the
/// first query index.
pub fn deep_terms_query0<A: AirExt>(
    air: &A,
    proof: &StarkProofExtP,
    extra_blowup_bits: u32,
    hasher: &Poseidon,
) -> (Vec<DeepTerm>, Fp2, Fp2) {
    deep_terms_query0_pub(air, proof, extra_blowup_bits, hasher, &[])
}

/// The query-0 form, preserved for callers that only attest the first query.
pub fn deep_terms_query0_pub<A: AirExt>(
    air: &A,
    proof: &StarkProofExtP,
    extra_blowup_bits: u32,
    hasher: &Poseidon,
    publics: &[Fp],
) -> (Vec<DeepTerm>, Fp2, Fp2) {
    deep_terms_queryk_pub(air, proof, extra_blowup_bits, hasher, publics, 0)
}

/// The DEEP terms of `proof`'s query `k`, its evaluation point `shift * omega^p_k`,
/// and the query's DEEP value. The transcript replay is identical to
/// `stark_verify_poseidon_ext`; the k-th consistency index is FRI's k-th
/// position under the seed the transcript hands FRI after the DEEP draw.
pub fn deep_terms_queryk_pub<A: AirExt>(
    air: &A,
    proof: &StarkProofExtP,
    extra_blowup_bits: u32,
    hasher: &Poseidon,
    publics: &[Fp],
    query: usize,
) -> (Vec<DeepTerm>, Fp2, Fp2) {
    let log_t = air.log_trace_len();
    let t = 1usize << log_t;
    let width = air.trace_width();
    let (log_n, _) = domain_params_blown(air, extra_blowup_bits);
    let n = 1usize << log_n;
    let window_size = air.window_size();

    let g = root_of_unity(log_t);
    let omega = root_of_unity(log_n);
    let shift = Fp::from_u64(SHIFT);

    let mut ts = PoseidonTranscript::new(hasher.clone());
    for &p in publics {
        ts.absorb(p);
    }
    ts.absorb_digest(&proof.trace_root);
    let coeffs: Vec<Fp2> = ts.challenge_powers(num_coeffs(air));
    ts.absorb_digest(&proof.comp_root);
    let z = draw_ood_point_poseidon(&mut ts, shift, n, t);
    for value in &proof.ood_frame {
        ts.absorb(value.c0);
        ts.absorb(value.c1);
    }
    let deep_coeffs: Vec<Fp2> = ts.challenge_powers(width * window_size + 1);

    let periodic_z: Vec<Fp2> = eval_cols_on_subgroup_ext(g, t, &air.periodic_columns(), z);
    let comp_z = compose_ext(air, g, z, &proof.ood_frame, &periodic_z, &coeffs);

    // FRI's positions under the seed this transcript hands it: the positions
    // the consistency queries open at.
    let s = ts.challenge_fp2();
    let positions = fri_positions_poseidon(&proof.fri, log_n, hasher, Some([s.c0, s.c1]));
    let p = positions.get(query).copied().unwrap_or(n);

    let qd = &proof.queries[query];
    let x = Fp2::from_base(shift * omega.pow(p as u64));

    let mut terms: Vec<DeepTerm> = Vec::with_capacity(width * window_size + 1);
    for k in 0..window_size {
        let zk = z * Fp2::from_base(g.pow(k as u64));
        for c in 0..width {
            terms.push(DeepTerm {
                val: Fp2::from_base(qd.trace[c]),
                claim: proof.ood_frame[k * width + c],
                point: zk,
                coeff: deep_coeffs[k * width + c],
            });
        }
    }
    terms.push(DeepTerm {
        val: qd.comp,
        claim: comp_z,
        point: z,
        coeff: deep_coeffs[width * window_size],
    });

    (terms, x, qd.deep)
}
