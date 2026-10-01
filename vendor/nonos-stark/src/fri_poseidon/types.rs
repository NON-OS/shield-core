// NONOS Operating System (AGPL-3.0-or-later)

//! The Poseidon-committed FRI proof: the same shape as the BLAKE3 one, but roots
//! and Merkle paths are rate-sized field digests, so the proof can be verified
//! by an AIR.

use super::super::air::RATE;
use super::super::field::Fp;
use alloc::vec::Vec;

/// One layer's contribution to a query: the value at the queried position and at
/// its negation, each with a Poseidon Merkle path to that layer's root.
pub struct LayerOpening {
    pub a: Fp,
    pub a_path: Vec<[Fp; RATE]>,
    pub b: Fp,
    pub b_path: Vec<[Fp; RATE]>,
}

/// The openings a single query induces across every folded layer.
pub struct QueryProof {
    pub layers: Vec<LayerOpening>,
}

/// A complete Poseidon-committed FRI proof.
pub struct FriProof {
    pub roots: Vec<[Fp; RATE]>,
    pub final_layer: Vec<Fp>,
    pub queries: Vec<QueryProof>,
}
