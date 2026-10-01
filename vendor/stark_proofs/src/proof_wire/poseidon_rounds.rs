// NONOS Operating System (AGPL-3.0-or-later)

//! The two round Poseidon form: the inner's wire layout.
//!
//! Same order as the keccak side and for the same reasons. The permutation root
//! and the row split lead, because a verifier absorbs that root before it
//! squeezes the composition coefficients and must reach it without reading a
//! sidecar several hundred kilobytes away. The split travels because a decoder
//! that guessed it would check two roots against halves of its own choosing and
//! still see two valid walks. The per query permutation paths trail, beside
//! nothing, so a chunked reader slices them the way it slices every other per
//! query section.
//!
//! This is not a superset of the one round form. A reader that accepted both
//! would let a prover present the encoding with no copy commitment in it.

use super::poseidon::{read_p_pre, serialize_p_pre};
use super::read::Reader;
use super::write::Writer;
use crate::crypto::stark::air::{StarkProofExtPRounds, RATE};
use alloc::vec::Vec;

/// Bytes before the one round encoding: the permutation root and the row split.
/// A digest here is four field elements rather than keccak's thirty two bytes,
/// so this is not the keccak header's length and the two are never the same
/// constant.
pub const P_ROUNDS_HEADER: usize = 8 * RATE + 4;

pub fn serialize_p_rounds(rounds: &StarkProofExtPRounds) -> Vec<u8> {
    let mut w = Writer::new();
    w.digest(&rounds.perm_root);
    w.u32(rounds.region_width);
    w.b.extend_from_slice(&serialize_p_pre(&rounds.pre));
    for path in &rounds.perm_paths {
        w.path(path);
    }
    w.b
}

pub fn deserialize_p_rounds(bytes: &[u8]) -> Option<StarkProofExtPRounds> {
    let mut r = Reader::new(bytes);
    let perm_root = r.digest()?;
    let region_width = r.u32()?;
    let pre = read_p_pre(&mut r)?;
    /*
     * One path per consistency query, and the count is the proof's rather than
     * a number on the wire. A count of its own would be a second opinion about
     * how many queries the proof has, and the two disagreeing is a row whose
     * permutation half nothing authenticates.
     */
    let mut perm_paths = Vec::with_capacity(pre.proof.queries.len());
    for _ in 0..pre.proof.queries.len() {
        perm_paths.push(r.path()?);
    }
    Some(StarkProofExtPRounds {
        pre,
        perm_root,
        region_width,
        perm_paths,
    })
}
