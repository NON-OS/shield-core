// NONOS Operating System (AGPL-3.0-or-later)

//! Encoding a base-field value as a Poseidon Merkle leaf.

use super::super::air::RATE;
use super::super::field::Fp;

/// A base-field value as a rate-sized leaf: `[v, 0, 0, 0]`.
pub fn pack_base(v: Fp) -> [Fp; RATE] {
    let mut d = [Fp::ZERO; RATE];
    d[0] = v;
    d
}
