// NONOS Operating System (AGPL-3.0-or-later)

//! The money-grade FRI proof: extension-field layers, plus a proof-of-work nonce
//! bound before the query positions. The layers are `Fp2` because the folds are
//! drawn from the extension.

use super::super::field::Fp2;
use super::super::fri::FOLD;
use alloc::vec::Vec;

/// One layer's contribution to a query: the `2^FRI_FOLD_LOG` extension
/// values a fold reads, at stride a quarter of the layer, under one Merkle
/// path.
///
/// They share a leaf because the fold reads all of them. One path per layer
/// rather than one per value is what makes the fold factor a lever that
/// shrinks a proof instead of growing it: a query pays three more field
/// elements a layer and half as many layers, and the paths are most of its
/// bytes. `v[0]` is the queried position; `v[j]` is that position plus `j`
/// quarters of the layer.
#[derive(Clone)]
pub struct LayerOpeningExt {
    pub v: [Fp2; FOLD],
    pub path: Vec<[u8; 32]>,
}

/// The openings a single query induces across every folded layer.
#[derive(Clone)]
pub struct QueryProofExt {
    pub layers: Vec<LayerOpeningExt>,
}

/// A complete money-grade FRI proof: extension-field challenges give ~2^-128
/// folding soundness, and the grinding nonce adds proof-of-work to the queries.
#[derive(Clone)]
pub struct FriProofExt {
    pub roots: Vec<[u8; 32]>,
    pub final_layer: Vec<Fp2>,
    pub queries: Vec<QueryProofExt>,
    pub pow_nonce: u64,
    /// The query grind's nonces after the first, in search order, when it is
    /// split (`GRIND_CHUNKS`). Each was found against the transcript with the
    /// one before it absorbed. Empty when the grind is one search.
    pub pow_chain: Vec<u64>,
    /// One proof-of-work nonce per layer, found after the layer's root is
    /// absorbed and before its fold challenge is drawn, when the commit rounds
    /// are ground. Empty otherwise. `COMMIT_GRIND_BITS`.
    pub fold_nonces: Vec<u64>,
}
