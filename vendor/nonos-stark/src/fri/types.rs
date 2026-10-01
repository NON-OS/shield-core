// NONOS Operating System (AGPL-3.0-or-later)

//! The FRI proof: commitment roots, the small final layer sent in full, and the
//! opened query positions that bind consecutive layers together.

use super::super::field::Fp;
use alloc::vec::Vec;

/// One layer's contribution to a query: the value at the queried position `i`
/// and at its negation `i + n/2`, each with a Merkle path to that layer's root.
pub struct LayerOpening {
    pub a: Fp,
    pub a_path: Vec<[u8; 32]>,
    pub b: Fp,
    pub b_path: Vec<[u8; 32]>,
}

/// The openings a single query induces across every folded layer.
pub struct QueryProof {
    pub layers: Vec<LayerOpening>,
}

/// A complete FRI low-degree proof.
pub struct FriProof {
    pub roots: Vec<[u8; 32]>,
    pub final_layer: Vec<Fp>,
    pub queries: Vec<QueryProof>,
}
