// NONOS Operating System (AGPL-3.0-or-later)
//! The Poseidon preprocessed prover in two commitment rounds.
//!
//! Identical to `pre` except for where the permutation challenges come from.
//! The region columns are interpolated and committed, their root goes into the
//! transcript, beta and gamma come out of it, and only then are the
//! permutation columns filled and committed.
//!
//! This is the inner's prover, so every choice here is one the recursion has
//! to model: two roots absorbed in this order, and one more chain opening per
//! query. The outer cannot verify a proof of this shape until it does.
//!
//! The join-split's copy constraint is argued at beta = 5 and gamma = 7 today,
//! set in four places under `shield/wire*.rs` and never drawn. It survives
//! only because none of the 371 cells its permutation binds is free of its
//! regions, which `the_join_split_leaves_no_cell_a_forgery_could_spend` gates.
//! This removes the reliance on that.

use super::super::super::field::{Fp, Fp2};
use super::super::super::fri_poseidon_ext::fri_prove_poseidon_ext_seeded;
use super::super::super::poseidon_merkle::{pack_pair_ext, pair_partner, PoseidonMerkleTree};
use super::super::super::poseidon_transcript::PoseidonTranscript;
use super::super::composition::num_coeffs;
use super::super::draw_ood_poseidon::draw_ood_point_poseidon;
use super::super::periodic_poseidon::periodic_tree_poseidon;
use super::super::poseidon::{Poseidon, RATE};
use super::super::prove_ext::{comp_at_z, ood_frame, over_domain, periodic_at_z, Domain};
use super::super::prove_ext_pre::pre_deep_over_domain;
use super::super::rounds::Permuted;
use super::super::spec::AirExt;
use super::super::wire::types_poseidon_ext::{StarkProofExtP, StarkQueryExtP};
use super::super::wire::types_poseidon_pre::{PeriodicOpeningP, StarkProofExtPPre};
use super::super::wire::types_poseidon_rounds::StarkProofExtPRounds;
use super::{queries, sidecar, trace};
use alloc::vec::Vec;

/// Prove `air` over `trace`, drawing the permutation challenges between the
/// two commitments.
///
/// `trace` arrives with its region columns final and its permutation columns
/// unset. `air` is handed back carrying the drawn challenges, because a
/// verifier has to evaluate the constraint set the composition was built from.
#[allow(clippy::too_many_arguments)]
pub fn stark_prove_poseidon_pre_rounds<A: AirExt + Permuted>(
    mut air: A,
    trace_row_major: &mut [Fp],
    n_queries: usize,
    grind_bits: u32,
    extra_blowup_bits: u32,
    h: &Poseidon,
    publics: &[Fp],
    blind: &[Vec<Fp>],
) -> Option<(StarkProofExtPRounds, A)> {
    let d = Domain::of(&air, extra_blowup_bits);
    let rw = air.region_width();
    if rw == 0 || rw >= d.width {
        return None;
    }

    let mut transcript = PoseidonTranscript::new(h.clone());
    for &p in publics {
        transcript.absorb(p);
    }

    // Round one: the regions' own witness, which depends on no challenge.
    let region = trace::commit_wide_cols(h, &d, trace_row_major, blind, 0, rw);
    let region_root = region.tree.root();
    transcript.absorb_digest(&region_root);

    /*
     * The point the copy constraint is checked at, fixed now that the columns
     * it speaks about are. A prover that wants a particular beta has to find a
     * region trace that hashes to it.
     */
    let lanes = air.challenge_lanes();
    let (beta, gamma) = super::super::compose_witness::draw_rounds_challenges(&mut transcript, lanes);
    if lanes == 2 {
        air.set_challenges_ext(beta, gamma);
    } else {
        air.set_challenges(beta.c0, gamma.c0);
    }
    air.fill_products(trace_row_major);

    /*
     * Round two. The products come from the trace's own values rather than the
     * blinded ones: the blinding vanishes on the trace domain, so the
     * accumulators the constraints see are the ones the wiring implies.
     */
    let perm = trace::commit_wide_cols(h, &d, trace_row_major, blind, rw, d.width);
    let perm_root = perm.tree.root();
    transcript.absorb_digest(&perm_root);

    let mut coeffs_all = region.coeffs.clone();
    coeffs_all.extend(perm.coeffs.clone());

    let coeffs: Vec<Fp2> = transcript.challenge_powers(num_coeffs(&air));

    let periodic_cols = air.periodic_columns();
    let (pc, p_tree) = periodic_tree_poseidon(&air, extra_blowup_bits, h);

    let comp_d = over_domain(&air, &d, &coeffs_all, &pc, &coeffs);
    let comp_half = comp_d.len() / 2;
    let comp_leaves: Vec<[Fp; RATE]> =
        crate::par::map_index(comp_half, |i| pack_pair_ext(comp_d[i], comp_d[i + comp_half]));
    let comp_tree = PoseidonMerkleTree::commit(h, &comp_leaves);
    transcript.absorb_digest(&comp_tree.root());

    let z = draw_ood_point_poseidon(&mut transcript, d.shift, d.n, d.t);
    let frame = ood_frame(&coeffs_all, &d, z);
    for value in &frame {
        transcript.absorb(value.c0);
        transcript.absorb(value.c1);
    }
    let periodic_z = periodic_at_z(&d, &periodic_cols, z);
    for value in &periodic_z {
        transcript.absorb(value.c0);
        transcript.absorb(value.c1);
    }
    let comp_z = comp_at_z(&air, &d, &frame, &periodic_z, z, &coeffs);

    let deep_coeffs: Vec<Fp2> =
        transcript.challenge_powers(d.width * d.window + 1 + periodic_cols.len());
    let deep_d = pre_deep_over_domain(
        &d,
        &coeffs_all,
        &pc,
        &comp_d,
        &frame,
        &periodic_z,
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
        &deep_d, d.shift, d.fri_log_blowup,
        n_queries,
        grind_bits,
        h,
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
    let deep_tree = PoseidonMerkleTree::commit(h, &deep_leaves);

    /*
     * The whole row still travels in one field, region half below the split
     * and permutation half above it. What doubles is the paths: each half
     * authenticates under the root of the round that committed it, and each
     * half's pruned chunk rebuilds from that half's own columns, so neither
     * path can be taken from a tree over the whole row.
     */
    let mut qs = Vec::with_capacity(n_queries);
    let mut openings: Vec<PeriodicOpeningP> = Vec::with_capacity(n_queries);
    let mut perm_paths: Vec<Vec<[Fp; RATE]>> = Vec::with_capacity(n_queries);
    for &p in &positions {
        let partner = pair_partner(p, d.n);
        let pair_leaf = p % (d.n / 2);
        qs.push(StarkQueryExtP {
            deep: deep_d[p],
            deep_sib: deep_d[partner],
            deep_path: deep_tree.open(pair_leaf),
            trace: trace::row_at(&d, &coeffs_all, p),
            trace_path: queries::open_half(h, &d, &region, p),
            comp: comp_d[p],
            comp_sib: comp_d[partner],
            comp_path: comp_tree.open(pair_leaf),
        });
        perm_paths.push(queries::open_half(h, &d, &perm, p));
        openings.push(sidecar::open(h, &d, &pc, &p_tree, p));
    }

    Some((
        StarkProofExtPRounds {
            pre: StarkProofExtPPre {
                proof: StarkProofExtP {
                    trace_root: region_root,
                    comp_root: comp_tree.root(),
                    ood_frame: frame,
                    fri,
                    queries: qs,
                },
                periodic_z,
                openings,
            },
            perm_root,
            region_width: rw,
            perm_paths,
        },
        air,
    ))
}
