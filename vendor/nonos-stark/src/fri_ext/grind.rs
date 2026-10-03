// NONOS Operating System (AGPL-3.0-or-later)

//! The launch transcript's grinds: how many bits, and in how many pieces.

/// Bits of proof-of-work before each folding challenge, on the launch
/// transcript. A radix-4 fold at the launch point is a degree-3 curve, 60.3
/// bits under the proximity-gaps bound, and it does not fall as queries rise.
/// A grind of `g` bits before each challenge makes every retry of that
/// challenge cost `2^g` hashes, which lifts the first fold to 80.3 bits of
/// work. It does not reach the DEEP batching challenge, which comes before
/// the folds (docs/12-soundness.md, Section 1).
#[cfg(not(feature = "fri8"))]
pub const COMMIT_GRIND_BITS: u32 = 20;
/// A radix-8 fold is a degree-7 curve, and 21 bits before each folding
/// challenge put the first fold at 80.1 bits under the 2020 bound (docs/17).
#[cfg(feature = "fri8")]
pub const COMMIT_GRIND_BITS: u32 = 21;

/// Bits of proof-of-work before the DEEP coefficients are drawn, one nonce
/// on the wire right after the periodic claims at z (docs/17 step 8). With
/// independent coefficients the DEEP round is one line's error, and 19 bits
/// put it at 80.9 under the 2020 bound.
pub const DEEP_GRIND_BITS: u32 = 19;

/// The accepted query shapes, as (id, queries, total query grind bits):
/// A, A' and B (docs/16). Each has its own query count, so the count names
/// the shape.
pub const QUERY_SHAPES: [(u8, usize, u32); 3] = [(1, 19, 28), (2, 18, 31), (3, 17, 33)];

/// The attestation point, for proofs a build makes once and a boot or spawn
/// gate checks: 26 queries after a 28-bit grind, about 100 bits on the query
/// phase where shape A has 80.8. The fold and DEEP rounds still bound the
/// provable figure at about 80 (docs/17); what this buys is the conjectured
/// margin, at a prover cost paid once per enrolled image. Kept apart from
/// `QUERY_SHAPES`, which are the pool's and which wallet code walks.
pub const ATTEST_SHAPE: (u8, usize, u32) = (4, 26, 28);

fn shapes() -> impl Iterator<Item = (u8, usize, u32)> {
    QUERY_SHAPES.into_iter().chain(core::iter::once(ATTEST_SHAPE))
}

/// The shape id a query count names on the format 7 transcript, zero for none.
pub fn shape_id(n_queries: usize) -> u8 {
    shapes()
        .find(|s| s.1 == n_queries)
        .map(|s| s.0)
        .unwrap_or(0)
}

/// Whether a query count and grind are one of the accepted shapes.
pub fn shape_accepts(n_queries: usize, grind_bits: u32) -> bool {
    shapes().any(|s| s.1 == n_queries && s.2 == grind_bits)
}

/// How many chained searches the query grind is split into, on the launch
/// transcript. `g` bits become this many grinds of `g - log2(GRIND_CHUNKS)`
/// bits, each absorbed before the next is searched, so a retry of the query
/// draw still costs `2^g` hashes on average; the time a prover waits is a sum
/// of eight draws instead of one, and its spread a third of the mean's instead
/// of all of it. A power of two.
pub const GRIND_CHUNKS: u32 = 8;
