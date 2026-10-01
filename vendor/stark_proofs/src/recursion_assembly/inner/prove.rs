// NONOS Operating System (AGPL-3.0-or-later)
//! Proving a join-split in two commitment rounds and packing the result.
//!
//! One place puts a join-split through the prover, so every entry proves the
//! same way: region columns committed, beta and gamma drawn against that root,
//! permutation columns committed second.

use super::types::{Inner, Rounds, Sidecar};
use crate::crypto::stark::air::{
    adopt_rounds_challenges, blinding_degree, blinding_poly, compose_inputs_pre_rounds,
    domain_params_blown, periodic_root_poseidon, stark_prove_poseidon_pre_rounds, Air, AirExt,
    Permuted, Poseidon, StarkProofExtPRounds, WiredMultiGen, RATE,
};
use crate::crypto::stark::field::Fp;
use crate::crypto::stark::fri::root_of_unity;
use crate::shield::join::JoinSplit;
use alloc::vec::Vec;

/// A proved join-split before it is wrapped: the AIR carrying the drawn
/// challenges, the proof, the statement it binds, and the baked periodic root.
pub struct Proved {
    pub air: WiredMultiGen,
    pub proof: StarkProofExtPRounds,
    pub publics: Vec<Fp>,
    pub root: [Fp; RATE],
}

pub fn prove_raw(
    h: &Poseidon,
    js: JoinSplit,
    nq: usize,
    grind: u32,
    extra_bits: u32,
    blind: &[Vec<Fp>],
) -> Proved {
    let publics = js.intent.clone();
    let root = periodic_root_poseidon(&js.wired, extra_bits, h);
    let mut witness = js.witness;
    let (proof, air) = stark_prove_poseidon_pre_rounds(
        js.wired,
        &mut witness,
        nq,
        grind,
        extra_bits,
        h,
        &publics,
        blind,
    )
    .expect("the deployed circuit carries permutation columns above its regions");
    Proved {
        air,
        proof,
        publics,
        root,
    }
}

/// Prove `js` and wrap it as an inner.
pub fn prove(
    h: &Poseidon,
    js: JoinSplit,
    nq: usize,
    grind: u32,
    extra_bits: u32,
    blind: &[Vec<Fp>],
) -> Inner<WiredMultiGen> {
    pack(
        h,
        prove_raw(h, js, nq, grind, extra_bits, blind),
        extra_bits,
        grind,
    )
}

/// The inner a proved join-split becomes. Its AIR must carry the challenges the
/// proof was made against: the prover leaves them in force, and a rebuilt AIR
/// adopts them through `adopt_rounds_challenges`.
pub fn pack(h: &Poseidon, p: Proved, extra_bits: u32, grind_bits: u32) -> Inner<WiredMultiGen> {
    let Proved {
        air,
        proof,
        publics,
        root,
    } = p;
    pack_air(h, air, proof, publics, root, extra_bits, grind_bits)
}

/// The inner any two round Poseidon proof becomes, for the AIR that made it.
///
/// `pack` is this over the deployed join-split. The wrap needs the same
/// packing over the settlement outer, which is a different AIR proved the
/// same way, so the packing is written once over the bound both satisfy
/// rather than once per circuit.
pub fn pack_air<A: AirExt + Permuted>(
    h: &Poseidon,
    mut air: A,
    proof: StarkProofExtPRounds,
    publics: Vec<Fp>,
    root: [Fp; RATE],
    extra_bits: u32,
    grind_bits: u32,
) -> Inner<A> {
    /*
     * The pair the proof was made under, drawn the way the verifier draws
     * it. An AIR that came back from the prover already holds it; one a
     * relayer rebuilt from the public words holds the constructor's
     * placeholder, and a composition witnessed over that pair is honest
     * arithmetic about a circuit nobody proved. Packing is the one place
     * every inner passes through, so the draw lives here rather than with
     * whichever caller remembered.
     */
    adopt_rounds_challenges(&mut air, h, &publics, &proof.pre.proof.trace_root);
    let ci = compose_inputs_pre_rounds(&air, &proof, extra_bits, h, &publics);
    let t = 1u64 << air.log_trace_len();
    let g = root_of_unity(air.log_trace_len());
    let StarkProofExtPRounds {
        pre,
        perm_root,
        region_width,
        perm_paths,
    } = proof;
    Inner {
        air,
        publics,
        proof: pre.proof,
        ci,
        t,
        g,
        extra: extra_bits,
        grind: grind_bits,
        sidecar: Some(Sidecar {
            periodic_z: pre.periodic_z,
            openings: pre.openings,
            root,
        }),
        rounds: Some(Rounds {
            perm_root,
            region_width,
            perm_paths,
        }),
    }
}

/// The Poseidon FRI's arity: a layer-zero leaf holds a fold pair.
pub const INNER_FRI_RADIX: usize = 2;

/// Added to a mask column's index to tag its trace values, so they never share
/// a counter block with any column's blinding. Below `2^31` so it is the same
/// number where `usize` is 32 bits, as in a browser's wasm32, and far above any
/// column index.
const MASK_TAG: usize = 1 << 30;

/// Make `js`'s proof hiding: fill its mask columns and return one blinding
/// polynomial per column, all expanded from `seed`.
///
/// Each query reads a column at every point of its fold pair and at each
/// point's successor, and the frame reads it at `z` and `g z`. A constrained
/// column's blinding covers all of those, `air::blinding_degree`.
///
/// A mask column takes random values on the trace domain and a blinding of
/// `bound - t` coefficients, so it is a uniform polynomial of degree below the
/// FRI bound. Values on the domain matter: a mask of the form `r Z_H` alone
/// would vanish there, folding keeps that factor, and FRI's final layer would
/// still read DEEP where the blinding is zero.
///
/// The seed must be fresh per proof: two spends under one seed share a blind,
/// and the difference of their openings cancels it back to the witness.
pub fn hide(h: &Poseidon, js: &mut JoinSplit, seed: &[Fp; RATE], nq: usize) -> Vec<Vec<Fp>> {
    hide_at(h, js, seed, nq, INNER_FRI_RADIX)
}

/// `hide` for a FRI of `radix` points per layer-zero leaf: 2 for the Poseidon
/// FRI the recursion verifies, `2^FRI_FOLD_LOG` for the Keccak FRI a chain
/// verifies directly.
pub fn hide_at(
    h: &Poseidon,
    js: &mut JoinSplit,
    seed: &[Fp; RATE],
    nq: usize,
    radix: usize,
) -> Vec<Vec<Fp>> {
    hide_wired(h, &js.wired, &mut js.witness, seed, nq, radix)
}

/// `hide_at` for any wired circuit and its witness: the join-split is one
/// caller, the device attestation another, and both hide by this code.
pub fn hide_wired(
    h: &Poseidon,
    air: &WiredMultiGen,
    witness: &mut [Fp],
    seed: &[Fp; RATE],
    nq: usize,
    radix: usize,
) -> Vec<Vec<Fp>> {
    let width = air.trace_width();
    let mask = air.wired().mask_columns();
    let t = 1usize << air.log_trace_len();
    let (log_n, fri_log_blowup) = domain_params_blown(air, 0);
    let bound = 1usize << (log_n - fri_log_blowup);
    for c in width - mask..width {
        for (r, v) in blinding_poly(h, seed, MASK_TAG + c, t - 1)
            .into_iter()
            .enumerate()
        {
            witness[r * width + c] = v;
        }
    }
    let deg = blinding_degree(nq, air.window_size(), radix);
    (0..width)
        .map(|c| {
            if c < width - mask {
                blinding_poly(h, seed, c, deg)
            } else {
                blinding_poly(h, seed, c, bound - t - 1)
            }
        })
        .collect()
}
