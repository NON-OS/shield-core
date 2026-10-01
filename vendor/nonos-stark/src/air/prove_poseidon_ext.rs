// NONOS Operating System (AGPL-3.0-or-later)

//! The Poseidon-committed money-grade DEEP STARK prover: the same construction as
//! `prove_ext`, but the trace, composition, and DEEP polynomial are committed with
//! Poseidon Merkle trees and the transcript is the Poseidon sponge, and the
//! low-degree test is the Poseidon money-grade FRI. Every step is then cheap to
//! re-verify inside a STARK, which is what makes a proof from here recursable.

use super::super::air::{Poseidon, RATE};
use super::super::field::{Fp, Fp2};
use super::super::fri::root_of_unity;
use super::super::fri_poseidon_ext::fri_prove_poseidon_ext_seeded;
use super::super::poly::eval_cols_on_subgroup_ext;
use super::super::poseidon_merkle::{pack_pair_ext, PoseidonMerkleTree};
use super::super::poseidon_transcript::PoseidonTranscript;
use super::composition::{compose_ext, domain_params_blown, num_coeffs};
use super::draw_ood_poseidon::draw_ood_point_poseidon;
use super::spec::AirExt;
use super::wire::types_poseidon_ext::{StarkProofExtP, StarkQueryExtP};
use alloc::vec::Vec;

/// The coset the evaluation domain sits on, from the one place that
/// defines it. The structure file publishes this value, so a private copy
/// is a second truth that stays 7 while the emit says otherwise.
use super::prove_ext::COSET_SHIFT as SHIFT;

/// Prove `trace` satisfies `air` at money-grade soundness, committed with Poseidon.
/// `extra_blowup_bits` sets the FRI rate exactly as the keccak prover.
pub fn stark_prove_poseidon_ext<A: AirExt>(
    air: &A,
    trace: &[Fp],
    n_queries: usize,
    grind_bits: u32,
    extra_blowup_bits: u32,
    hasher: &Poseidon,
) -> StarkProofExtP {
    stark_prove_poseidon_ext_pub(
        air,
        trace,
        n_queries,
        grind_bits,
        extra_blowup_bits,
        hasher,
        &[],
        &[],
    )
}

/// The hiding Poseidon prover: the same proof with each trace column blinded by
/// `blind[c] * Z_H`, so the query openings reveal nothing about the witness. This
/// is the prover the deployed transfer runs on; the blinding is what makes the
/// proof itself, not only the commitments, hide the amounts and the link.
/// `blind[c]` is the prover's secret blinding polynomial for column `c` (one per
/// column, degree at least `n_queries`), from private entropy via `blinding_poly`.
/// The proof verifies under the plain `stark_verify_poseidon_ext_pub`.
#[allow(clippy::too_many_arguments)]
pub fn stark_prove_poseidon_ext_zk<A: AirExt>(
    air: &A,
    trace: &[Fp],
    n_queries: usize,
    grind_bits: u32,
    extra_blowup_bits: u32,
    hasher: &Poseidon,
    publics: &[Fp],
    blind: &[Vec<Fp>],
) -> StarkProofExtP {
    stark_prove_poseidon_ext_pub(
        air,
        trace,
        n_queries,
        grind_bits,
        extra_blowup_bits,
        hasher,
        publics,
        blind,
    )
}

/// The same prover, seeding the transcript with `publics` before the trace roots so
/// the proof is bound to those public inputs by Fiat-Shamir. A recursive verifier
/// replays the same seed, exposing the publics in its transcript column.
#[allow(clippy::too_many_arguments)]
pub fn stark_prove_poseidon_ext_pub<A: AirExt>(
    air: &A,
    trace: &[Fp],
    n_queries: usize,
    grind_bits: u32,
    extra_blowup_bits: u32,
    hasher: &Poseidon,
    publics: &[Fp],
    blind: &[Vec<Fp>],
) -> StarkProofExtP {
    let log_t = air.log_trace_len();
    let t = 1usize << log_t;
    let width = air.trace_width();
    let (log_n, fri_log_blowup) = domain_params_blown(air, extra_blowup_bits);
    let n = 1usize << log_n;
    let window_size = air.window_size();

    let g = root_of_unity(log_t);
    let shift = Fp::from_u64(SHIFT);

    let mut transcript = PoseidonTranscript::new(hasher.clone());
    for &p in publics {
        transcript.absorb(p);
    }
    // The whole trace under one root: the extension is transient, hashed row
    // by row into a pruned tree and dropped, and the transcript absorbs one
    // digest however wide the trace is.
    let d = super::prove_ext::Domain::of(air, extra_blowup_bits);
    let wt = super::poseidon_prove::commit_wide(hasher, &d, trace, blind);
    let trace_coeffs = &wt.coeffs;
    transcript.absorb_digest(&wt.tree.root());

    let coeffs: Vec<Fp2> = transcript.challenge_powers(num_coeffs(air));

    let periodic_cols = air.periodic_columns();
    // Composition and DEEP run the shared streamed passes: the trace exists as
    // coefficients, each pass extends one coset at a time, and the arithmetic
    // is the keccak path's to the element. Only the transcript and the trees
    // differ between the two provers now.
    let pc = super::prove_ext::periodic_coeffs(&periodic_cols, &d);
    let comp_d = super::prove_ext::over_domain(air, &d, trace_coeffs, &pc, &coeffs);
    let comp_half = comp_d.len() / 2;
    let comp_leaves: Vec<[Fp; RATE]> =
        crate::par::map_index(comp_half, |i| pack_pair_ext(comp_d[i], comp_d[i + comp_half]));
    let comp_tree = PoseidonMerkleTree::commit(hasher, &comp_leaves);
    transcript.absorb_digest(&comp_tree.root());

    let z = draw_ood_point_poseidon(&mut transcript, shift, n, t);
    let ood_frame = super::prove_ext::ood_frame(trace_coeffs, &d, z);
    for value in &ood_frame {
        transcript.absorb(value.c0);
        transcript.absorb(value.c1);
    }

    let periodic_z: Vec<Fp2> = eval_cols_on_subgroup_ext(g, t, &periodic_cols, z);
    let comp_z = compose_ext(air, g, z, &ood_frame, &periodic_z, &coeffs);

    let deep_coeffs: Vec<Fp2> = transcript.challenge_powers(width * window_size + 1);

    let deep_d = super::prove_ext::deep_over_domain(
        &d,
        trace_coeffs,
        &comp_d,
        &ood_frame,
        comp_z,
        z,
        &deep_coeffs,
    );

    /*
     * The seed, then FRI: it draws the positions after its nonce, and every
     * consistency query below opens at them.
     */
    let s = transcript.challenge_fp2();
    let (fri, positions) = fri_prove_poseidon_ext_seeded(
        &deep_d, shift, fri_log_blowup,
        n_queries,
        grind_bits,
        hasher,
        Some([s.c0, s.c1]),
    );
    /*
     * The DEEP codeword is FRI layer zero, so this tree must be the tree the
     * FRI built: fold pairs under one leaf, half as many leaves. Committing it
     * per value here and per pair there would give two roots for one codeword,
     * and the consistency openings would authenticate under a root the
     * transcript never absorbed.
     */
    let deep_half = deep_d.len() / 2;
    let deep_leaves: Vec<[Fp; RATE]> =
        crate::par::map_index(deep_half, |i| pack_pair_ext(deep_d[i], deep_d[i + deep_half]));
    let deep_tree = PoseidonMerkleTree::commit(hasher, &deep_leaves);

    let mut queries: Vec<StarkQueryExtP> = Vec::with_capacity(n_queries);
    for &p in &positions {
        queries.push(super::poseidon_prove::open_query(
            hasher, &d, &wt, &comp_d, &comp_tree, &deep_d, &deep_tree, p,
        ));
    }

    StarkProofExtP {
        trace_root: wt.tree.root(),
        comp_root: comp_tree.root(),
        ood_frame,
        fri,
        queries,
    }
}
