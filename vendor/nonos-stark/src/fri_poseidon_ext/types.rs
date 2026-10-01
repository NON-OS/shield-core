// NONOS Operating System (AGPL-3.0-or-later)

//! The proof shape of the Poseidon-committed money-grade FRI: extension-field
//! layer openings under Poseidon Merkle roots, so the whole low-degree test can be
//! re-verified inside a STARK. The keccak `fri_ext` is the Solidity-cheap outer
//! form; this is the circuit-cheap inner form recursion folds over.

use super::super::air::RATE;
use super::super::field::{Fp, Fp2};
use alloc::vec::Vec;

/// One layer's opening at a query: the values at `i` and at `i + half` under a
/// single Poseidon Merkle path.
///
/// They share a leaf because a fold reads both. Committing them apart bought a
/// second path per layer and nothing else, and it is why raising the fold factor
/// made a proof larger rather than smaller: a fold of `k` paid `k` paths where a
/// shared leaf pays one. THREAT 6a.
#[derive(Clone)]
pub struct LayerOpeningExtP {
    pub a: Fp2,
    pub b: Fp2,
    pub path: Vec<[Fp; RATE]>,
}

/// A single query across every folded layer.
#[derive(Clone)]
pub struct QueryProofExtP {
    pub layers: Vec<LayerOpeningExtP>,
}

/// A complete Poseidon-committed extension FRI proof.
#[derive(Clone)]
pub struct FriProofExtP {
    pub roots: Vec<[Fp; RATE]>,
    pub final_layer: Vec<Fp2>,
    pub queries: Vec<QueryProofExtP>,
    pub pow_nonce: u64,
}
