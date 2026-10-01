// NONOS Operating System (AGPL-3.0-or-later)

use crate::crypto::stark::air::RATE;
use crate::crypto::stark::field::Fp;

/// Published in spec/shield-key-hierarchy.json, which the wallet and the client
/// derive against. Changing either value changes every note, so amend the spec
/// and regenerate the vector rather than editing here.
pub const SPEND_DOMAIN: u64 = 0x5350_4E44;
pub const NULL_DOMAIN: u64 = 0x4E55_4C4C;

/// Lane one of the word a dead input's nullifier hashes beside its position.
///
/// The pool spends both nullifiers of every intent and cannot do otherwise:
/// liveness is private, no public word carries it, and a word that did would
/// publish how many notes each payment spent. So a dummy's nullifier is retired
/// on chain like a real one, and it has to live where a real one cannot. A live
/// input pins this lane to zero and a dead one to this, so the two absorb
/// different words and a dummy reaches a real nullifier only through a Poseidon
/// collision rather than through a prover's choice.
pub const DEAD_DOMAIN: u64 = 0x4445_4144;

pub fn tag(v: u64) -> [Fp; RATE] {
    let mut q = [Fp::ZERO; RATE];
    q[0] = Fp::from_u64(v);
    q
}

/// The word the fourth compression absorbs: the position the path recovered,
/// and the lane that says whether this input is a note or a dummy.
pub fn position_word(index: u64, live: bool) -> [Fp; RATE] {
    let mut q = tag(index);
    q[1] = if live { Fp::ZERO } else { Fp::from_u64(DEAD_DOMAIN) };
    q
}
