// NONOS Operating System (AGPL-3.0-or-later)

//! Extracting a Poseidon-committed proof's query-`k` authentication openings: the
//! DEEP value against the FRI root and the composition against the composition
//! root, at the k-th consistency query position. These are the flat, equal-depth
//! openings the inner verifier authenticates before it trusts the DEEP algebra.
//! The trace row is not here: under the wide commitment it authenticates as one
//! compress-chain-plus-path opening, the same shape the periodic sidecar uses,
//! and the recursion builds that opening beside these.

use super::super::fri_poseidon_ext::fri_positions_poseidon;
use super::super::field::{Fp, Fp2};
use super::super::poseidon_merkle::pair_at;
use super::super::poseidon_transcript::PoseidonTranscript;
use super::composition::domain_params_blown;
use super::draw_ood_poseidon::draw_ood_point_poseidon;
use super::multi_membership::Opening;
use super::poseidon::RATE;
use super::spec::AirExt;
use super::wire::types_poseidon_ext::StarkProofExtP;
use super::Poseidon;
use alloc::vec::Vec;

/// The coset the evaluation domain sits on, from the one place that
/// defines it. The structure file publishes this value, so a private copy
/// is a second truth that stays 7 while the emit says otherwise.
use super::prove_ext::COSET_SHIFT as SHIFT;

/// The query-0 openings, preserved for callers that only attest the first query.
pub fn query_openings_query0<A: AirExt>(
    air: &A,
    proof: &StarkProofExtP,
    extra_blowup_bits: u32,
    hasher: &Poseidon,
    publics: &[Fp],
) -> (Vec<Opening>, usize) {
    query_openings_queryk(air, proof, extra_blowup_bits, hasher, publics, 0)
}

/// The query-`k` openings, replaying the transcript to the k-th consistency query
/// index exactly as `stark_verify_poseidon_ext` does (FRI's k-th position under
/// the seed the transcript hands it), then packaging each authenticated opening (leaf, root, path,
/// directions) the same batched membership consumes. The `directions` are the bits
/// of `p_k`, so authenticating them binds the openings to that index.
pub fn query_openings_queryk<A: AirExt>(
    air: &A,
    proof: &StarkProofExtP,
    extra_blowup_bits: u32,
    hasher: &Poseidon,
    publics: &[Fp],
    query: usize,
) -> (Vec<Opening>, usize) {
    let log_t = air.log_trace_len();
    let t = 1usize << log_t;
    let (log_n, _) = domain_params_blown(air, extra_blowup_bits);
    let n = 1usize << log_n;
    let shift = Fp::from_u64(SHIFT);

    let mut ts = PoseidonTranscript::new(hasher.clone());
    for &p in publics {
        ts.absorb(p);
    }
    ts.absorb_digest(&proof.trace_root);
    // The alphas the coefficient vectors are powers of: drawn to move the
    // sponge, not used here.
    let _alpha: Fp2 = ts.challenge_fp2();
    ts.absorb_digest(&proof.comp_root);
    let _z = draw_ood_point_poseidon(&mut ts, shift, n, t);
    for value in &proof.ood_frame {
        ts.absorb(value.c0);
        ts.absorb(value.c1);
    }
    let _deep_alpha: Fp2 = ts.challenge_fp2();
    // FRI's positions under the seed this transcript hands it: the positions
    // the consistency queries open at.
    let s = ts.challenge_fp2();
    let positions = fri_positions_poseidon(&proof.fri, log_n, hasher, Some([s.c0, s.c1]));
    let p = positions.get(query).copied().unwrap_or(n);

    let qd = &proof.queries[query];
    /*
     * Both codewords commit as fold pairs, so a position opens the leaf that
     * holds it and the directions are the bits of that leaf's index, one fewer
     * than the domain has. The third value `pair_at` returns is which half the
     * position occupies, and the assembly binds it to the same index scalar
     * these directions are bound to.
     */
    let (deep_i, deep_leaf, _) = pair_at(p, n, qd.deep, qd.deep_sib);
    let (_, comp_leaf, _) = pair_at(p, n, qd.comp, qd.comp_sib);
    let depth = qd.deep_path.len();
    let directions: Vec<bool> = (0..depth).map(|lv| (deep_i >> lv) & 1 == 1).collect();

    // The DEEP value against the FRI root (the same authentication the fold's
    // opened value already relies on) and the composition against the
    // composition root. The trace row's chain opening is built beside these.
    (
        alloc::vec![
            Opening {
                leaf: deep_leaf,
                root: proof.fri.roots[0],
                siblings: qd.deep_path.clone(),
                directions: directions.clone(),
            },
            Opening {
                leaf: comp_leaf,
                root: proof.comp_root,
                siblings: qd.comp_path.clone(),
                directions,
            },
        ],
        p,
    )
}

/// The preprocessed twin: the walk comes from `replay` with the claims, so
/// the index this derives is the one the sidecar prover drew. `perm` is the
/// second commitment root when the inner was proved in two rounds, without
/// which every index past it is a different draw. Only the opening list lives
/// here.
#[allow(clippy::too_many_arguments)]
pub fn query_openings_pre_queryk<A: AirExt>(
    air: &A,
    proof: &StarkProofExtP,
    periodic_z: &[Fp2],
    perm: Option<&[Fp; RATE]>,
    extra_blowup_bits: u32,
    hasher: &Poseidon,
    publics: &[Fp],
    query: usize,
) -> (Vec<Opening>, usize) {
    let n = super::replay::domain_size(air, extra_blowup_bits);
    let mut r = super::replay::replay(
        air,
        proof,
        Some(periodic_z),
        perm,
        extra_blowup_bits,
        hasher,
        publics,
    );
    let p = super::replay::query_index(&mut r, n, query);

    let qd = &proof.queries[query];
    let (deep_i, deep_leaf, _) = pair_at(p, n, qd.deep, qd.deep_sib);
    let (_, comp_leaf, _) = pair_at(p, n, qd.comp, qd.comp_sib);
    let depth = qd.deep_path.len();
    let directions: Vec<bool> = (0..depth).map(|lv| (deep_i >> lv) & 1 == 1).collect();

    (
        alloc::vec![
            Opening {
                leaf: deep_leaf,
                root: proof.fri.roots[0],
                siblings: qd.deep_path.clone(),
                directions: directions.clone(),
            },
            Opening {
                leaf: comp_leaf,
                root: proof.comp_root,
                siblings: qd.comp_path.clone(),
                directions,
            },
        ],
        p,
    )
}
