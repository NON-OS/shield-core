// NONOS Operating System (AGPL-3.0-or-later)

//! The Poseidon-committed money-grade FRI prover: the same extension-field fold as
//! `fri_ext`, but every layer is committed with a Poseidon Merkle tree and the
//! transcript is the Poseidon sponge, so a proof made here can have its Merkle
//! openings, folds, and challenges re-derived inside a STARK. That is what makes it
//! the inner form for recursion.

use super::super::air::{Poseidon, RATE};
use super::super::field::{Fp, Fp2};
use super::super::fri::{final_coefficients, fold_ext, n_folds as folds_of, root_of_unity, stop_log};
use super::super::poseidon_merkle::{pack_pair_ext, PoseidonMerkleTree};
use super::super::poseidon_transcript::PoseidonTranscript;
use super::types::{FriProofExtP, LayerOpeningExtP, QueryProofExtP};
use alloc::vec::Vec;

/// Prove `codeword` (an `Fp2` evaluation vector over `shift * {omega^i}`) has
/// degree below `2^k / 2^log_blowup`, committing with Poseidon and grinding
/// `grind_bits` of proof-of-work. `hasher` is shared by the Merkle nodes and the
/// transcript.
pub fn fri_prove_poseidon_ext(
    codeword: &[Fp2],
    shift: Fp,
    log_blowup: u32,
    n_queries: usize,
    grind_bits: u32,
    hasher: &Poseidon,
) -> FriProofExtP {
    fri_prove_poseidon_ext_seeded(codeword, shift, log_blowup, n_queries, grind_bits, hasher, None).0
}

/// The same proof seeded by a STARK's transcript, with the positions it drew.
///
/// The STARK's consistency check runs at these positions, so it is ground
/// with FRI: they are drawn after the nonce. `seed` is the STARK transcript's
/// extension challenge after its DEEP draw, absorbed as two elements before
/// layer zero. `None` is a standalone FRI.
pub fn fri_prove_poseidon_ext_seeded(
    codeword: &[Fp2],
    shift: Fp,
    log_blowup: u32,
    n_queries: usize,
    grind_bits: u32,
    hasher: &Poseidon,
    seed: Option<[Fp; 2]>,
) -> (FriProofExtP, Vec<usize>) {
    let n = codeword.len();
    let log_n = n.trailing_zeros();
    let n_folds = folds_of(log_n, log_blowup);
    let base_omega = root_of_unity(log_n);
    let inv2 = Fp::from_u64(2).inv();

    let mut transcript = PoseidonTranscript::new(hasher.clone());
    if let Some([s0, s1]) = seed {
        transcript.absorb(s0);
        transcript.absorb(s1);
    }
    let mut current: Vec<Fp2> = codeword.to_vec();
    let mut layers: Vec<Vec<Fp2>> = Vec::with_capacity(n_folds);
    let mut trees: Vec<PoseidonMerkleTree> = Vec::with_capacity(n_folds);
    let mut roots: Vec<[Fp; RATE]> = Vec::with_capacity(n_folds);

    let mut omega = base_omega;
    let mut coset = shift;
    for _ in 0..n_folds {
        /*
         * A leaf per fold rather than per value: the pair the next layer is
         * computed from sits under one digest, so a query pays one path per
         * layer and the tree has half the leaves and one level less.
         */
        let half_n = current.len() / 2;
        let leaves: Vec<[Fp; RATE]> =
            crate::par::map_index(half_n, |i| pack_pair_ext(current[i], current[i + half_n]));
        let tree = PoseidonMerkleTree::commit(hasher, &leaves);
        let root = tree.root();
        transcript.absorb_digest(&root);
        let beta = transcript.challenge_fp2();
        let next = fold_ext(&current, beta, coset, omega, inv2);
        layers.push(current);
        trees.push(tree);
        roots.push(root);
        current = next;
        omega = omega.square();
        coset = coset.square();
    }

    // The final polynomial's coefficients, absorbed in place of the layer.
    let final_layer = final_coefficients(&current, coset, omega, stop_log(log_n, log_blowup));
    for value in &final_layer {
        transcript.absorb(value.c0);
        transcript.absorb(value.c1);
    }
    let pow_nonce = transcript.grind(grind_bits);

    let mut queries: Vec<QueryProofExtP> = Vec::with_capacity(n_queries);
    let mut positions: Vec<usize> = Vec::with_capacity(n_queries);
    for _ in 0..n_queries {
        let q = transcript.challenge_index(n);
        positions.push(q);
        let mut opened: Vec<LayerOpeningExtP> = Vec::with_capacity(n_folds);
        for m in 0..n_folds {
            let half = n >> (m + 1);
            let i = q % half;
            let layer = &layers[m];
            let tree = &trees[m];
            opened.push(LayerOpeningExtP {
                a: layer[i],
                b: layer[i + half],
                path: tree.open(i),
            });
        }
        queries.push(QueryProofExtP { layers: opened });
    }

    (FriProofExtP { roots, final_layer, queries, pow_nonce }, positions)
}
