// NONOS Operating System (AGPL-3.0-or-later)

//! The preprocessed prover driver: the same transcript walk as the plain path, but the
//! periodic schedule enters as a baked root rather than a recomputed region. It absorbs the
//! claimed periodic values after the frame, widens the DEEP coefficient draw to cover one
//! quotient per periodic column, and opens the sidecar row per query. The schedule bake is the
//! half of the settlement circuit this deletes, so a proof carries claims and opened rows in
//! place of the recompute.

use super::super::super::field::Fp2;
use super::super::super::fri_ext::fri_prove_ext_layer_zero;
use super::super::super::merkle::MerkleTree;
use super::super::super::transcript::Transcript;
use super::super::composition::num_coeffs;
use super::super::periodic_root::periodic_tree_over;
use super::super::progress::{Phase, Progress};
use super::super::prove_ext::{
    comp_at_z, draw_ood_point_ext, ood_frame, over_domain, periodic_coeffs, trace_coeffs,
    wide_streamed, Domain,
};
use super::super::spec::AirExt;
use super::super::wire::types_ext::StarkProofExt;
use super::super::wire::types_ext_pre::StarkProofExtPre;
use super::{deep, queries};
use crate::field::Fp;
use crate::poly::eval_coeff_cols_at_ext;
use alloc::vec::Vec;

/*
 * Phase timing, so a long run says where it is instead of printing nothing
 * between its first line and its last. A settlement proof runs for hours and
 * the only signal used to be that the process was still alive, which is the
 * difference between waiting and being blind. Present only under the parallel
 * feature, which is the build that has a standard library to print with.
 */

/// Prove `trace` against `air` with the periodic sidecar, at the given FRI
/// rate. The verifier must hold the matching baked periodic root.
///
/// The transcript order below is the protocol and matches the materialized
/// prover this replaced; the periodic tree comes through the same helper a
/// registered root does, so the two are one object by construction. Nothing is
/// held over the full domain but the two Fp2 codewords and the leaf digests.
/// Returns `None` only when a watcher asked the prover to stop. This entry
/// point passes no watcher, so it returns `Some` for every input it accepts;
/// the option is still in the signature rather than unwrapped here, because
/// unwrapping would put a panic on the one path a caller cannot influence.
pub fn stark_prove_ext_preprocessed<A: AirExt>(
    air: &A,
    trace: &[Fp],
    n_queries: usize,
    grind_bits: u32,
    extra_blowup_bits: u32,
) -> Option<StarkProofExtPre> {
    stark_prove_ext_preprocessed_watched(air, trace, n_queries, grind_bits, extra_blowup_bits, None)
}

/// The same proof, with somebody watching.
///
/// `watch` carries the phase the prover is in, the timing of each phase as it
/// completes, and the caller's request to stop. A shell polls it; the prover
/// never calls back, because a callback out of a worker thread is a contract
/// about threads and lifetimes and a poll is an atomic load.
///
/// Returns `None` when the caller cancelled, so a cancelled proof cannot be
/// mistaken for a finished one by a reader who ignores the watch.
pub fn stark_prove_ext_preprocessed_watched<A: AirExt>(
    air: &A,
    trace: &[Fp],
    n_queries: usize,
    grind_bits: u32,
    extra_blowup_bits: u32,
    watch: Option<&Progress>,
) -> Option<StarkProofExtPre> {
    stark_prove_ext_preprocessed_tree(
        air,
        trace,
        n_queries,
        grind_bits,
        extra_blowup_bits,
        &[],
        None,
        watch,
    )
    .map(|(pre, _)| pre)
}

/// The same proof, with the periodic tree carried in and out.
///
/// The periodic commitment is a constant of the circuit: it depends on the
/// periodic columns and the rate and on nothing the witness changes, which is
/// why its root can be baked into a verifier. It was nonetheless rebuilt for
/// every proof, half the running time of a settlement proof spent recomputing
/// a value that had not moved, because the openings need the tree and only the
/// root had been kept. A caller that holds the tree passes it here and the
/// phase costs the interpolation of the columns and nothing else; a caller
/// that does not gets the tree back beside the proof, to keep.
///
/// A supplied tree that does not fit the domain is not used: the tree is
/// rebuilt and the rebuilt one returned, so a stale cache costs the old time
/// and never a wrong proof. The proof is verified against the baked root by
/// whoever asked for it, and a tree with the right shape and the wrong
/// contents fails there.
///
/// `publics` are the statement's public inputs, absorbed into the transcript
/// first of all, before the trace root, one field element each in order. A
/// verifier absorbs the same words at the same point and derives the same
/// challenges; one that absorbs different words derives different ones and
/// the proof fails at its first query. That is what makes the proof a proof
/// about these inputs rather than about some inputs: without it an accepted
/// proof could be presented for any statement of the same shape. An empty
/// slice absorbs nothing and leaves the transcript as it was.
#[allow(clippy::too_many_arguments)]
pub fn stark_prove_ext_preprocessed_tree<A: AirExt>(
    air: &A,
    trace: &[Fp],
    n_queries: usize,
    grind_bits: u32,
    extra_blowup_bits: u32,
    publics: &[Fp],
    periodic_tree: Option<MerkleTree>,
    watch: Option<&Progress>,
) -> Option<(StarkProofExtPre, MerkleTree)> {
    let d = Domain::of(air, extra_blowup_bits);
    let mut phase = Phase::start(watch);

    let mut transcript = Transcript::new(b"NONOS-STARK-EXT");
    transcript.absorb_fp_vec(publics);
    let tc = trace_coeffs(trace, &d);
    let trace_tree = wide_streamed(&tc, &d);
    let trace_root = trace_tree.root();
    transcript.absorb_digest(&trace_root);
    phase.done("trace commitment");
    if phase.cancelled() {
        return None;
    }

    let coeffs: Vec<Fp2> = (0..num_coeffs(air))
        .map(|_| transcript.challenge_fp2())
        .collect();

    /*
     * The columns are built once and handed to the committer, which drops them
     * as soon as it has interpolated them. Building them here and again inside
     * the committer paid for the construction twice and held two copies of a
     * set that is gigabytes wide on the settlement outer.
     *
     * Everything below wanted them for two things: the count, and the value at
     * the out-of-domain point. The count is taken before the handover and the
     * value comes off the coefficients, which are the same polynomials.
     */
    let (pc, p_tree) = match periodic_tree {
        Some(tree) if tree.len() == d.n => {
            let cols = air.periodic_columns();
            let pc = periodic_coeffs(&cols, &d);
            if !super::super::periodic_root::tree_is_of(&pc, &d, &tree) {
                return None;
            }
            (pc, tree)
        }
        _ => periodic_tree_over(air.periodic_columns(), &d),
    };
    let n_periodic = pc.len();
    phase.done("periodic commitment");
    if phase.cancelled() {
        return None;
    }
    let comp_d = over_domain(air, &d, &tc, &pc, &coeffs);
    let comp_tree = MerkleTree::commit_ext(&comp_d);
    transcript.absorb_digest(&comp_tree.root());
    phase.done("composition");
    if phase.cancelled() {
        return None;
    }

    let z = draw_ood_point_ext(&mut transcript, d.shift, d.n, d.t);
    let frame = ood_frame(&tc, &d, z);
    transcript.absorb_fp2_vec(&frame);
    let periodic_z = eval_coeff_cols_at_ext(&pc, z);
    transcript.absorb_fp2_vec(&periodic_z);
    let comp_z = comp_at_z(air, &d, &frame, &periodic_z, z, &coeffs);
    phase.done("out of domain");
    if phase.cancelled() {
        return None;
    }

    let deep_coeffs: Vec<Fp2> = (0..d.width * d.window + 1 + n_periodic)
        .map(|_| transcript.challenge_fp2())
        .collect();
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

    /*
     * FRI draws the positions after its nonce, seeded by everything above, and
     * the consistency queries open at those positions: one set, ground once.
     */
    let seed = transcript.challenge_seed();
    let (fri, _, positions) = fri_prove_ext_layer_zero(
        &deep_d,
        d.shift,
        d.fri_log_blowup,
        n_queries,
        grind_bits,
        Some(&seed),
    );
    phase.done("deep and fri");
    if phase.cancelled() {
        return None;
    }

    let (qs, openings) = queries::open(
        &positions,
        &d,
        &tc,
        &trace_tree,
        &pc,
        &p_tree,
        &comp_d,
        &comp_tree,
    );
    phase.done("query openings");
    if let Some(w) = watch {
        w.finish();
    }
    let pre = StarkProofExtPre {
        deep_nonce: 0,
        proof: StarkProofExt {
            trace_root,
            comp_root: comp_tree.root(),
            ood_frame: frame,
            fri,
            queries: qs,
        },
        periodic_z,
        openings,
    };
    Some((pre, p_tree))
}
