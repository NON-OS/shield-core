// NONOS Operating System (AGPL-3.0-or-later)

//! Encoding extension-field values as Poseidon Merkle leaves.

use super::super::air::RATE;
use super::super::field::{Fp, Fp2};

/// An extension value as a rate-sized leaf: `[c0, c1, 0, 0]`.
pub fn pack_ext(v: Fp2) -> [Fp; RATE] {
    let mut d = [Fp::ZERO; RATE];
    d[0] = v.c0;
    d[1] = v.c1;
    d
}

/// A fold's two inputs as one leaf: `[a.c0, a.c1, b.c0, b.c1]`.
///
/// A fold always reads both, so committing them apart buys a second path per
/// layer and nothing else. The pair fills the rate exactly, so the leaf costs
/// what one value cost and the tree holds half the leaves: one path fewer to
/// carry and one level less to walk. THREAT 6a.
pub fn pack_pair_ext(a: Fp2, b: Fp2) -> [Fp; RATE] {
    [a.c0, a.c1, b.c0, b.c1]
}

/// The position sharing a leaf with `p` over a domain of `n`: `p + n/2` from the
/// low half, `p - n/2` from the high one.
pub fn pair_partner(p: usize, n: usize) -> usize {
    p ^ (n / 2)
}

/// Where a full-domain position opens in a tree of fold pairs: the leaf index,
/// the leaf with its two values in the order it holds them, and which half `p`
/// itself occupies.
///
/// The leaf index is `p % (n/2)` and never `p >> 1`. The two agree for every `p`
/// below the half and diverge above it, so a shift authenticates a real leaf of
/// the same tree for most positions and the wrong one for the rest: a failure
/// that looks intermittent rather than wrong. The rule lives here and not at
/// each caller for that reason.
pub fn pair_at(p: usize, n: usize, value: Fp2, partner: Fp2) -> (usize, [Fp; RATE], bool) {
    let half = n / 2;
    let high = p >= half;
    let (a, b) = if high { (partner, value) } else { (value, partner) };
    (p % half, pack_pair_ext(a, b), high)
}
