// NONOS Operating System (AGPL-3.0-or-later)
//! A Poseidon preprocessed proof whose trace was committed in two rounds.
//!
//! Same shape as the keccak side's `StarkProofExtRounds` and for the same
//! reason: the region columns are committed first, the permutation challenges
//! come out of the transcript against that root, and the permutation columns
//! are committed second. So the trace has two roots and a query's row has two
//! paths, one per half.
//!
//! This is the inner's format. The outer verifies an inner in circuit, so
//! every field here has to be something the recursion can model: two roots it
//! absorbs in the right order, and one more chain opening per query.

use super::super::poseidon::RATE;
use super::super::super::field::Fp;
use super::types_poseidon_pre::StarkProofExtPPre;
use alloc::vec::Vec;

#[derive(Clone)]
pub struct StarkProofExtPRounds {
    pub pre: StarkProofExtPPre,
    /// Root of the second round, over the permutation columns alone.
    pub perm_root: [Fp; RATE],
    /// Where the row splits. Emitted rather than assumed: a verifier that
    /// split it anywhere else would check two roots against the wrong halves
    /// and still see two valid walks.
    pub region_width: usize,
    /// Per query, in `pre.proof.queries` order: the path authenticating the
    /// permutation half of that row under `perm_root`.
    pub perm_paths: Vec<Vec<[Fp; RATE]>>,
}
