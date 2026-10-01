// NONOS Operating System (AGPL-3.0-or-later)

use super::limbs::POOL_LOG_ROUNDS;
use crate::crypto::stark::air::RATE;
use alloc::vec::Vec;

/// Lanes 0..4 spend_pk, lanes 4..8 blinding.
pub fn owner_row(base: usize) -> usize {
    base
}

/// Lanes 0..4 `[value_lo, value_hi, asset, NOTE_DOMAIN]`, lanes 4..8 the owner.
pub fn public_row(base: usize, span_op: usize) -> usize {
    base + span_op
}

/// The commitment.
pub fn cm_row(base: usize, span_op: usize) -> usize {
    base + span_op + (1usize << POOL_LOG_ROUNDS)
}

/// The owner digest feeds the second compression's sibling half. Lane by lane:
/// a digest is four elements and binding one lane leaves the other three free.
pub fn note_edges(base: usize, span_op: usize) -> Vec<(usize, usize, usize, usize)> {
    let owner = base + (1usize << POOL_LOG_ROUNDS);
    let second = public_row(base, span_op);
    let mut sw = Vec::with_capacity(RATE);
    for c in 0..RATE {
        sw.push((owner, c, second, RATE + c));
    }
    sw
}
