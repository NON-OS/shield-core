// NONOS Operating System (AGPL-3.0-or-later)

//! The preprocessed-periodic proof: a money-grade proof plus the periodic
//! sidecar a deployment verifier consumes instead of recomputing the
//! structural columns. The claims at z are transcript-absorbed before the
//! DEEP coefficients are drawn, and each consistency query carries the wide
//! periodic row with one path against the baked periodic commitment.

use super::super::super::field::{Fp, Fp2};
use super::types_ext::StarkProofExt;
use alloc::vec::Vec;

/// One consistency query's periodic opening: every periodic-column value at
/// the query row, authenticated by a single wide-leaf path.
#[derive(Clone)]
pub struct PeriodicOpeningExt {
    pub row: Vec<Fp>,
    pub path: Vec<[u8; 32]>,
}

/// A money-grade proof with the periodic sidecar. `openings` parallels the
/// proof's consistency queries in order.
#[derive(Clone)]
pub struct StarkProofExtPre {
    pub proof: StarkProofExt,
    /// The claimed periodic-column evaluations at the out-of-domain point.
    pub periodic_z: Vec<Fp2>,
    pub openings: Vec<PeriodicOpeningExt>,
    /// The nonce ground before the DEEP coefficients are drawn (docs/17
    /// step 8). Zero, and not on the wire, on every v1 proof.
    pub deep_nonce: u64,
}
