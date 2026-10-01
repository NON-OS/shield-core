// NONOS Operating System (AGPL-3.0-or-later)

//! The money-grade FRI prover. It lifts the base codeword into the extension,
//! commits each layer over `Fp2`, folds under an extension challenge, grinds a
//! proof-of-work nonce, then opens the sampled positions.

use super::super::field::{Fp, Fp2};
use super::super::fri::FRI_FOLD_LOG;
use super::super::fri::{final_coefficients, final_log, fold_ext, n_layers, root_of_unity};
use super::super::merkle::MerkleTree;
use super::super::transcript::Transcript;
use super::types::{FriProofExt, LayerOpeningExt, QueryProofExt};
use alloc::vec::Vec;

/// Prove `codeword` (an extension-field evaluation vector over the size-`2^k`
/// domain `shift * {omega^i}`) has degree below `2^k / 2^log_blowup`, with
/// extension-field folding and `grind_bits` of proof-of-work. `codeword.len()`
/// must be a power of two. A base codeword is lifted with `Fp2::from_base` by the
/// caller; the DEEP quotient is already `Fp2`, so it is passed directly.
pub fn fri_prove_ext(
    codeword: &[Fp2],
    shift: Fp,
    log_blowup: u32,
    n_queries: usize,
    grind_bits: u32,
) -> FriProofExt {
    fri_prove_ext_layer_zero(codeword, shift, log_blowup, n_queries, grind_bits, None).0
}

/// The same proof seeded by a STARK's transcript, with the tree of its first
/// layer and the positions it drew.
///
/// A STARK's consistency check runs at FRI's positions and reads its DEEP
/// value from FRI's layer-zero opening there (`deep_leaf`). The positions are
/// drawn after the nonce, so the consistency check is ground with FRI; when it
/// drew positions of its own from the STARK transcript, a prover could re-roll
/// them for the price of one re-blinded commitment, and the check stood on its
/// queries alone. `seed` is the STARK transcript's `challenge_seed` after its
/// last draw, absorbed before layer zero, so the positions depend on the whole
/// proof. `None` is a standalone FRI.
pub fn fri_prove_ext_layer_zero(
    codeword: &[Fp2],
    shift: Fp,
    log_blowup: u32,
    n_queries: usize,
    grind_bits: u32,
    seed: Option<&[u8; 32]>,
) -> (FriProofExt, MerkleTree, Vec<usize>) {
    fri_prove_ext_layer_zero_ground(
        codeword, shift, log_blowup, n_queries, grind_bits, 0, 1, seed,
    )
}

/// `fri_prove_ext_layer_zero` with `commit_grind` bits of proof-of-work before
/// each folding challenge: after a layer's root is absorbed, a nonce is found
/// and absorbed, and only then is the challenge drawn. Zero grinds nothing and
/// writes no nonces. `grind_chunks` splits the query grind into that many
/// chained searches of `grind_bits - log2(grind_chunks)` bits; one is a single
/// search, as before.
#[allow(clippy::too_many_arguments)]
pub fn fri_prove_ext_layer_zero_ground(
    codeword: &[Fp2],
    shift: Fp,
    log_blowup: u32,
    n_queries: usize,
    grind_bits: u32,
    commit_grind: u32,
    grind_chunks: u32,
    seed: Option<&[u8; 32]>,
) -> (FriProofExt, MerkleTree, Vec<usize>) {
    let n = codeword.len();
    let log_n = n.trailing_zeros();
    let n_layers = n_layers(log_n, log_blowup);
    let base_omega = root_of_unity(log_n);
    let inv2 = Fp::from_u64(2).inv();

    let mut transcript = Transcript::new(b"NONOS-STARK-FRI-EXT");
    if let Some(seed) = seed {
        transcript.absorb_digest(seed);
    }
    let mut current: Vec<Fp2> = codeword.to_vec();
    let mut layers: Vec<Vec<Fp2>> = Vec::with_capacity(n_layers);
    let mut trees: Vec<MerkleTree> = Vec::with_capacity(n_layers);
    let mut roots: Vec<[u8; 32]> = Vec::with_capacity(n_layers);
    let mut fold_nonces: Vec<u64> = Vec::new();

    let mut omega = base_omega;
    let mut coset = shift;
    for _ in 0..n_layers {
        let tree = MerkleTree::commit_groups(&current);
        let root = tree.root();
        transcript.absorb_digest(&root);
        if commit_grind > 0 {
            fold_nonces.push(transcript.grind(commit_grind));
        }
        let beta = transcript.challenge_fp2();
        /*
         * A layer is `FRI_FOLD_LOG` halvings under one challenge and its
         * powers: folding with beta and then with beta squared over the
         * squared domain is the radix-two argument applied twice, so the
         * soundness is the one we already have and the degree claim is
         * unchanged. What it buys is one Merkle path where there were two.
         */
        let mut next = fold_ext(&current, beta, coset, omega, inv2);
        let mut b = beta * beta;
        let (mut w, mut c) = (omega.square(), coset.square());
        for _ in 1..FRI_FOLD_LOG {
            next = fold_ext(&next, b, c, w, inv2);
            b = b * b;
            w = w.square();
            c = c.square();
        }
        layers.push(current);
        trees.push(tree);
        roots.push(root);
        current = next;
        omega = w;
        coset = c;
    }

    // Bind the final layer, then grind: the proof-of-work nonce is committed
    // before any query position is drawn, so it cannot be re-searched per query.
    // The final polynomial's coefficients, absorbed in place of the layer.
    let final_layer = final_coefficients(&current, coset, omega, final_log(log_n, log_blowup));
    transcript.absorb_fp2_vec(&final_layer);
    // v2, on the launch transcript (the split query grind): the query shape,
    // before the query grind, so a grind counts for one shape only (docs/16).
    #[cfg(feature = "v2")]
    if grind_chunks > 1 {
        transcript.absorb_shape(super::shape_id(n_queries));
    }
    // Chained: each search runs against the transcript with the previous
    // nonce absorbed, so none can be searched before the one before it is
    // found, and all of them are behind the final layer.
    let per_chunk = chunk_bits(grind_bits, grind_chunks);
    let pow_nonce = transcript.grind(per_chunk);
    let pow_chain: Vec<u64> = (1..grind_chunks.max(1))
        .map(|_| transcript.grind(per_chunk))
        .collect();

    let mut queries: Vec<QueryProofExt> = Vec::with_capacity(n_queries);
    let mut positions: Vec<usize> = Vec::with_capacity(n_queries);
    for _ in 0..n_queries {
        let q = transcript.challenge_index(n);
        positions.push(q);
        let mut opened: Vec<LayerOpeningExt> = Vec::with_capacity(n_layers);
        for m in 0..n_layers {
            // The layer's size, and the stride a fold group spans it at.
            let size = n >> (m * FRI_FOLD_LOG as usize);
            let stride = size >> FRI_FOLD_LOG;
            let i = q % stride;
            let layer = &layers[m];
            let tree = &trees[m];
            opened.push(LayerOpeningExt {
                v: core::array::from_fn(|j| layer[i + j * stride]),
                path: tree.open(i),
            });
        }
        queries.push(QueryProofExt { layers: opened });
    }

    // at least one layer is always committed, so the fallback never runs
    let zero = trees
        .into_iter()
        .next()
        .unwrap_or_else(|| MerkleTree::commit_groups(codeword));
    (
        FriProofExt {
            roots,
            final_layer,
            queries,
            pow_nonce,
            pow_chain,
            fold_nonces,
        },
        zero,
        positions,
    )
}

/// Bits per search when `grind_bits` are split `chunks` ways: `chunks` is a
/// power of two, and the expected work of all of them is `2^grind_bits`.
pub(crate) fn chunk_bits(grind_bits: u32, chunks: u32) -> u32 {
    grind_bits.saturating_sub(chunks.max(1).trailing_zeros())
}
