// NONOS Operating System (AGPL-3.0-or-later)

//! The proof shape of the Poseidon-committed money-grade STARK: the same DEEP
//! proof as `StarkProofExt`, but every commitment is a Poseidon Merkle root and
//! every path is Poseidon, so the whole verification is cheap to re-run inside a
//! STARK. This is the inner proof a recursive verifier folds over; the keccak
//! `StarkProofExt` is the outer proof an on-chain verifier checks.

use super::super::super::field::{Fp, Fp2};
use super::super::super::fri_poseidon_ext::FriProofExtP;
use super::super::poseidon::RATE;
use alloc::vec::Vec;

#[derive(Clone)]
pub struct StarkQueryExtP {
    pub deep: Fp2,
    /// The value sharing `deep`'s leaf: the DEEP codeword at `p ^ (n/2)`.
    ///
    /// Layer zero of the FRI is this codeword and its leaves hold fold pairs, so
    /// a consistency query at `p` opens the leaf holding `p` and its partner.
    /// Carrying the partner costs one extension value and saves the second path
    /// the old shape spent on every query of every layer. THREAT 6a.
    pub deep_sib: Fp2,
    pub deep_path: Vec<[Fp; RATE]>,
    pub trace: Vec<Fp>,
    /// One path for the whole row: the leaf is the row's compress-chain
    /// digest, the rule `hash_periodic_row` fixes.
    pub trace_path: Vec<[Fp; RATE]>,
    pub comp: Fp2,
    /// The same for the composition, to the same depth. Nothing folds it, so
    /// this buys no path of its own; it keeps a query's three openings equal
    /// depth, which is what lets the batched authentication be one region. A
    /// composition tree over single values would be one level deeper than the
    /// other two and the set could not be one region.
    pub comp_sib: Fp2,
    pub comp_path: Vec<[Fp; RATE]>,
}

#[derive(Clone)]
pub struct StarkProofExtP {
    /// The whole trace under one root: leaf i is the compress-chain digest of
    /// row i. One absorb, one path per query, however wide the trace.
    pub trace_root: [Fp; RATE],
    pub comp_root: [Fp; RATE],
    /// The trace columns at `g^k * z` for each window row `k`, row-major in `Fp2`.
    pub ood_frame: Vec<Fp2>,
    pub fri: FriProofExtP,
    pub queries: Vec<StarkQueryExtP>,
}
