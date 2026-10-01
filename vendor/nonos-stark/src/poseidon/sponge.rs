// NONOS Operating System (AGPL-3.0-or-later)

//! A field sponge over the Poseidon-Goldilocks permutation: rate 8, capacity
//! 4, width 12. Absorb pads the input to a multiple of the rate, XORs (adds)
//! each block into the rate lanes, and permutes; squeeze reads the rate lanes.
//! The capacity is never touched by the input, which is the domain separation
//! that makes the sponge a hash.

use super::super::field::Fp;
use super::constants::WIDTH;
use super::permutation::permute;
use alloc::vec::Vec;

/// The sponge rate: input lanes absorbed per permutation.
pub const RATE: usize = 8;
/// The sponge capacity: lanes reserved for security, never absorbed.
pub const CAPACITY: usize = WIDTH - RATE;
/// The default digest width in field elements.
pub const DIGEST: usize = 4;

/// Hash a slice of field elements to a `DIGEST`-element digest. The input is
/// padded with zeros to a whole number of rate blocks; the length is folded in
/// through the initial capacity so inputs of different length that share a
/// zero-padded prefix do not collide.
pub fn hash(input: &[Fp]) -> [Fp; DIGEST] {
    let mut state = [Fp::ZERO; WIDTH];
    // Length separation in the first capacity lane.
    state[RATE] = Fp::from_u64(input.len() as u64);

    let mut padded: Vec<Fp> = input.to_vec();
    while !padded.len().is_multiple_of(RATE) {
        padded.push(Fp::ZERO);
    }

    for block in padded.chunks(RATE) {
        for (i, &v) in block.iter().enumerate() {
            state[i] = state[i] + v;
        }
        state = permute(state);
    }

    let mut out = [Fp::ZERO; DIGEST];
    out.copy_from_slice(&state[..DIGEST]);
    out
}

/// Compress two digests into one, the two-to-one map a Merkle tree needs.
pub fn compress(left: &[Fp; DIGEST], right: &[Fp; DIGEST]) -> [Fp; DIGEST] {
    let mut state = [Fp::ZERO; WIDTH];
    state[..DIGEST].copy_from_slice(left);
    state[DIGEST..2 * DIGEST].copy_from_slice(right);
    state = permute(state);
    let mut out = [Fp::ZERO; DIGEST];
    out.copy_from_slice(&state[..DIGEST]);
    out
}
