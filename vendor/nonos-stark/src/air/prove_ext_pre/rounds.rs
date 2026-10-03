// NONOS Operating System (AGPL-3.0-or-later)
//! The preprocessed prover in two commitment rounds.
//!
//! Identical to `run` except for where the permutation challenges come from.
//! The region columns are interpolated and committed, their root goes into the
//! transcript, beta and gamma come out of it, and only then are the
//! permutation columns filled and committed. Everything after that is the same
//! walk over a trace that now has two roots.
//!
//! This is the whole difference between a copy constraint that is argued and
//! one that is asserted: with the challenges fixed in the circuit, a prover
//! could choose a trace in which two cells it says are equal are not.

use super::super::super::field::Fp;
use super::super::super::fri_ext::fri_prove_ext_layer_zero_ground;
use super::super::super::merkle::{hash_leaf_ext, hash_leaf_wide, MerkleTree, TreeTop};
use super::super::super::transcript::Transcript;
use super::super::composition::num_coeffs;
use super::super::periodic_root::periodic_tree_over;
use super::super::prove_ext::{
    comp_at_z, draw_ood_point_ext, eval_base, ood_frame, over_domain, periodic_coeffs,
    trace_coeffs_cols, wide_streamed, Domain,
};

/// Levels of the trace trees kept below their tops: an opening rebuilds
/// `2^TRACE_CUT` rows from the column polynomials. Each full tree held
/// 2^24 digests, half a gigabyte; its top at 3 holds an eighth of that.
const TRACE_CUT: usize = 3;
/// The composition tree's cut: its leaves are values already in memory, so
/// rebuilding a chunk is only hashing.
const COMP_CUT: usize = 6;
use super::super::rounds::Permuted;
use super::super::spec::AirExt;
use super::super::wire::types_ext::StarkProofExt;
use super::super::wire::types_ext_pre::StarkProofExtPre;
use super::super::wire::types_ext_rounds::StarkProofExtRounds;
use super::{deep, queries};
use crate::poly::eval_coeff_cols_at_ext;
use alloc::vec::Vec;

/// Prove `air` over `trace`, drawing the permutation challenges between the two
/// commitments.
///
/// `trace` arrives with its region columns final and its permutation columns
/// unset; this fills them once the challenges exist. `air` is taken by value
/// and handed back with the drawn challenges in force, because a verifier has
/// to evaluate the same constraint set the composition was built from.
///
/// `blind` is one polynomial per trace column, or empty for the plain,
/// non-hiding prover. A proof opens `n_queries` rows of the trace and a frame
/// of `window_size` more, so a column that is not blinded hands those cells to
/// anyone who reads the proof. For a pool whose whole claim is that a spend
/// reveals nothing, that is the difference between a private transfer and a
/// transfer whose witness is legible at 32 positions.
#[allow(clippy::too_many_arguments)]
pub fn stark_prove_ext_rounds<A: AirExt + Permuted>(
    air: A,
    trace: &mut [Fp],
    n_queries: usize,
    grind_bits: u32,
    extra_blowup_bits: u32,
    publics: &[Fp],
    periodic_tree: Option<MerkleTree>,
    blind: &[Vec<Fp>],
) -> Option<(StarkProofExtRounds, MerkleTree, A)> {
    let src = match periodic_tree {
        Some(t) => Periodic::Cached(t),
        None => Periodic::Build,
    };
    let (rounds, tree, air) = prove_rounds(
        air,
        trace,
        n_queries,
        grind_bits,
        extra_blowup_bits,
        publics,
        src,
        blind,
        &|_| true,
    )?;
    Some((rounds, tree?, air))
}

/// `stark_prove_ext_rounds` opening the periodic tree from its top, the levels
/// above a cut, and recomputing each queried chunk: the same paths and root
/// without building or holding the tree. What a device proves with.
#[allow(clippy::too_many_arguments)]
pub fn stark_prove_ext_rounds_top<A: AirExt + Permuted>(
    air: A,
    trace: &mut [Fp],
    n_queries: usize,
    grind_bits: u32,
    extra_blowup_bits: u32,
    publics: &[Fp],
    top: &TreeTop,
    blind: &[Vec<Fp>],
) -> Option<(StarkProofExtRounds, A)> {
    let (rounds, _, air) = prove_rounds(
        air,
        trace,
        n_queries,
        grind_bits,
        extra_blowup_bits,
        publics,
        Periodic::Top(top),
        blind,
        &|_| true,
    )?;
    Some((rounds, air))
}

/// `stark_prove_ext_rounds_top` reporting each phase to `observe`, which
/// returns false to stop the proof there. `None` when it was stopped, or for
/// the reasons the plain form gives; the caller that stopped it knows which.
#[allow(clippy::too_many_arguments)]
pub fn stark_prove_ext_rounds_top_observed<A: AirExt + Permuted>(
    air: A,
    trace: &mut [Fp],
    n_queries: usize,
    grind_bits: u32,
    extra_blowup_bits: u32,
    publics: &[Fp],
    top: &TreeTop,
    blind: &[Vec<Fp>],
    observe: &dyn Fn(&'static str) -> bool,
) -> Option<(StarkProofExtRounds, A)> {
    let (rounds, _, air) = prove_rounds(
        air,
        trace,
        n_queries,
        grind_bits,
        extra_blowup_bits,
        publics,
        Periodic::Top(top),
        blind,
        observe,
    )?;
    Some((rounds, air))
}

/// Where the periodic tree's paths come from.
enum Periodic<'a> {
    Build,
    Cached(MerkleTree),
    Top(&'a TreeTop),
}

#[allow(clippy::too_many_arguments)]
fn prove_rounds<A: AirExt + Permuted>(
    mut air: A,
    trace: &mut [Fp],
    n_queries: usize,
    grind_bits: u32,
    extra_blowup_bits: u32,
    publics: &[Fp],
    periodic: Periodic<'_>,
    blind: &[Vec<Fp>],
    observe: &dyn Fn(&'static str) -> bool,
) -> Option<(StarkProofExtRounds, Option<MerkleTree>, A)> {
    let d = Domain::of(&air, extra_blowup_bits);
    /*
     * Each phase boundary reports its memory when asked and hands the phase to
     * the caller's observer, which can stop the proof there: a wallet shows
     * progress and cancels between phases, never inside one.
     */
    let phase = |name: &'static str| -> bool {
        crate::par::mark(name);
        observe(name)
    };
    let rw = air.region_width();
    assert!(
        rw < d.width,
        "a two round proof needs permutation columns above the regions, got {rw} of {}",
        d.width
    );
    assert!(
        blind.is_empty() || blind.len() == d.width,
        "one blinding polynomial per trace column, or none at all"
    );

    /*
     * f + r * (x^t - 1), which is f itself on the trace domain and random off
     * it, so every constraint still holds where it is checked and no opened
     * row is the witness. Applied per column as its coefficients are taken,
     * because the two rounds interpolate their halves at different moments.
     */
    let hide = |c: Vec<Vec<Fp>>, lo: usize| -> Vec<Vec<Fp>> {
        if blind.is_empty() {
            return c;
        }
        c.into_iter()
            .enumerate()
            .map(|(j, cf)| crate::poly::blind_coeffs(&cf, d.t, &blind[lo + j]))
            .collect()
    };

    let mut transcript = Transcript::new(b"NONOS-STARK-EXT");
    transcript.absorb_fp_vec(publics);

    /*
     * Round one. The region columns are the prover's own witness and nothing
     * here depends on a challenge, so they commit first and their root is what
     * the challenges are drawn against.
     */
    let region_c = hide(trace_coeffs_cols(trace, &d, 0, rw), 0);
    let region_top = TreeTop::of(&wide_streamed(&region_c, &d), TRACE_CUT)?;
    let region_root = region_top.root();
    transcript.absorb_digest(&region_root);
    if !phase("region committed") {
        return None;
    }

    /*
     * The point the copy constraint is checked at, fixed now that the columns
     * it speaks about are. A prover that wants a particular beta has to find a
     * region trace that hashes to it.
     */
    let (beta, gamma) = super::super::replay_pre::draw_rounds_challenges_keccak(
        &mut transcript,
        air.challenge_lanes(),
    );
    super::super::replay_pre::adopt_pair(&mut air, beta, gamma);
    air.fill_products(trace);

    /*
     * Round two. The products are built from the trace's own values rather
     * than the blinded ones, which is what makes this sound: blinding vanishes
     * on the trace domain, so the accumulators the constraints see are the
     * accumulators the wiring implies.
     */
    let perm_c = hide(trace_coeffs_cols(trace, &d, rw, d.width), rw);
    let perm_top = TreeTop::of(&wide_streamed(&perm_c, &d), TRACE_CUT)?;
    let perm_root = perm_top.root();
    transcript.absorb_digest(&perm_root);
    if !phase("products committed") {
        return None;
    }

    let mut tc = region_c;
    tc.extend(perm_c);

    let coeffs = super::super::replay_pre::draw_composition_coeffs(
        &mut transcript,
        num_coeffs(&air),
        air.challenge_lanes(),
    );

    let (pc, p_tree, top) = match periodic {
        Periodic::Cached(tree) if tree.len() == d.n => {
            let cols = air.periodic_columns();
            let pc = periodic_coeffs(&cols, &d);
            if !super::super::periodic_root::tree_is_of(&pc, &d, &tree) {
                return None;
            }
            (pc, Some(tree), None)
        }
        Periodic::Top(top) => {
            if top.leaves() != d.n {
                return None;
            }
            (
                periodic_coeffs(&air.periodic_columns(), &d),
                None,
                Some(top),
            )
        }
        _ => {
            let (pc, tree) = periodic_tree_over(air.periodic_columns(), &d);
            (pc, Some(tree), None)
        }
    };
    let n_periodic = pc.len();
    if !phase("periodic") {
        return None;
    }

    let comp_d = over_domain(&air, &d, &tc, &pc, &coeffs);
    if !phase("composition") {
        return None;
    }
    let comp_top = TreeTop::of(&MerkleTree::commit_ext(&comp_d), COMP_CUT)?;
    let comp_root = comp_top.root();
    transcript.absorb_digest(&comp_root);
    if !phase("composition tree") {
        return None;
    }

    let z = draw_ood_point_ext(&mut transcript, d.shift, d.n, d.t);
    let mut frame = ood_frame(&tc, &d, z);
    if let Some(pair) = air.mask_pair() {
        super::super::replay_pre::mask_pair_frame(&mut frame, d.width, d.window, pair);
    }
    transcript.absorb_fp2_vec(&frame);
    let periodic_z = eval_coeff_cols_at_ext(&pc, z);
    transcript.absorb_fp2_vec(&periodic_z);
    let comp_z = comp_at_z(&air, &d, &frame, &periodic_z, z, &coeffs);

    let (mut deep_coeffs, deep_nonce) = super::super::replay_pre::draw_deep_coeffs_ground(
        &mut transcript,
        d.width * d.window + 1 + n_periodic,
        air.challenge_lanes(),
    );
    if let Some(pair) = air.mask_pair() {
        super::super::replay_pre::mask_pair_coeffs(&mut deep_coeffs, d.width, d.window, pair);
    }
    let deep_d = deep::over_domain(
        &d,
        &tc,
        &pc,
        &comp_d,
        &frame,
        &periodic_z,
        comp_z,
        z,
        &deep_coeffs,
    );
    if !phase("deep") {
        return None;
    }

    /*
     * FRI draws the positions after its nonce, seeded by everything above, and
     * the consistency queries open at those positions: one set, ground once.
     */
    let seed = transcript.challenge_seed();
    let (fri, _, positions) = fri_prove_ext_layer_zero_ground(
        &deep_d,
        d.shift,
        d.fri_log_blowup,
        n_queries,
        grind_bits,
        super::super::replay_pre::commit_grind_bits(air.challenge_lanes()),
        super::super::replay_pre::grind_chunks(air.challenge_lanes()),
        Some(&seed),
    );
    drop(deep_d);
    if !phase("fri") {
        return None;
    }

    /*
     * The three trees were kept as their tops. Each opening rebuilds the
     * chunk under its position: trace rows from the column polynomials, the
     * composition's leaves from its values, and hashes them up to the stored
     * level. The paths and roots are the full trees'.
     */
    let row_chunk = |cols: &[Vec<Fp>], top: &TreeTop, p: usize| -> Vec<[u8; 32]> {
        let base = p & !(top.chunk() - 1);
        let digests: Vec<[u8; 32]> = crate::par::map_index(top.chunk(), |k| {
            let x = d.shift * d.omega.pow((base + k) as u64);
            let row: Vec<Fp> = cols.iter().map(|cf| eval_base(cf, x)).collect();
            hash_leaf_wide(&row)
        });
        top.open(p, &digests)
    };
    let region_open = |p: usize| row_chunk(&tc[..rw], &region_top, p);
    let perm_open = |p: usize| row_chunk(&tc[rw..], &perm_top, p);
    let comp_open = |p: usize| {
        let base = p & !(comp_top.chunk() - 1);
        let digests: Vec<[u8; 32]> = comp_d[base..base + comp_top.chunk()]
            .iter()
            .map(|v| hash_leaf_ext(*v))
            .collect();
        comp_top.open(p, &digests)
    };

    let (qs, openings, perm_paths) = queries::open_rounds(
        &positions,
        &d,
        &tc,
        &region_open,
        &perm_open,
        &pc,
        &|p: usize| match (&p_tree, top) {
            (Some(tree), _) => tree.open(p),
            (None, Some(top)) => {
                let base = p & !(top.chunk() - 1);
                top.open(
                    p,
                    &super::super::periodic_root::periodic_chunk(&pc, &d, base, top.chunk()),
                )
            }
            (None, None) => Vec::new(),
        },
        &comp_d,
        &comp_open,
    );
    if !phase("queries") {
        return None;
    }

    let rounds = StarkProofExtRounds {
        pre: StarkProofExtPre {
            deep_nonce,
            proof: StarkProofExt {
                trace_root: region_root,
                comp_root,
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
    };
    Some((rounds, p_tree, air))
}
