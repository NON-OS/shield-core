// NONOS Operating System (AGPL-3.0-or-later)
//! What Ethereum charges, before any of our code runs.
//!
//! Three rules decide whether a settlement fits in one transaction, and none
//! of them is ours: the per-transaction gas cap, the calldata token pricing,
//! and memory expansion. They are written here once so the parameter search
//! and the cost model read the same arithmetic, and so a change to any of
//! them lands in one place when the chain changes it.

/// EIP-7825: the most gas a single transaction may consume. Not the block,
/// the transaction. There is no bidding past it and no splitting the work
/// without inventing a protocol for the half that never lands.
pub const TX_GAS_CAP: u64 = 16_777_216;

/// The intrinsic cost of a transaction existing.
pub const BASE_TX_GAS: u64 = 21_000;

/// EIP-7623: a zero byte is one token, a nonzero byte four.
pub const TOKENS_PER_NONZERO_BYTE: u64 = 4;

/// Gas per calldata token on the standard branch.
pub const GAS_PER_TOKEN: u64 = 4;

/// Gas per calldata token on the floor branch, which prices transactions that
/// carry data and barely execute. A verifier is the opposite case, so this
/// branch does not bind for us, but a search that assumed so without checking
/// would be wrong for some point it has not tried yet.
pub const FLOOR_GAS_PER_TOKEN: u64 = 10;

/// Calldata tokens for a payload of `zero` and `nonzero` bytes.
pub fn tokens(zero: u64, nonzero: u64) -> u64 {
    zero + TOKENS_PER_NONZERO_BYTE * nonzero
}

/// Tokens for a payload of `len` bytes at a measured nonzero ratio.
///
/// A proof's zero-byte count is not known until it exists, so a search over
/// parameters has to estimate it. The ratio is measured on the shipped
/// artifact rather than assumed: 2,503 zero bytes in 112,436, so 97.77 per
/// cent nonzero. Field elements and digests are close to uniform, so the
/// ratio is a property of the encoding rather than of that one proof, but it
/// is an estimate and every number derived from it is too.
pub fn tokens_estimated(len: u64) -> u64 {
    let nonzero = len * SHIPPED_NONZERO / SHIPPED_TOTAL;
    tokens(len - nonzero, nonzero)
}

/// Nonzero bytes in the shipped artifact, and its length. The ratio these
/// give is the one `tokens_estimated` uses.
pub const SHIPPED_NONZERO: u64 = 109_933;
/// Total bytes of the shipped artifact.
pub const SHIPPED_TOTAL: u64 = 112_436;

/// What a transaction pays for `tokens` of calldata and `execution` gas of
/// work: `21000 + max(4T + execution, 10T)`.
pub fn transaction_gas(tokens: u64, execution: u64) -> u64 {
    let standard = GAS_PER_TOKEN * tokens + execution;
    let floor = FLOOR_GAS_PER_TOKEN * tokens;
    BASE_TX_GAS + if standard > floor { standard } else { floor }
}

/// Execution gas left under the cap after the base cost and this much
/// calldata, or `None` if the calldata alone does not fit.
pub fn execution_budget(tokens: u64) -> Option<u64> {
    let fixed = BASE_TX_GAS + GAS_PER_TOKEN * tokens;
    TX_GAS_CAP.checked_sub(fixed)
}

/// The EVM's memory expansion cost for a high-water mark of `words`.
///
/// `3w + w^2/512`. The second term is why a verifier that materialises a
/// little per query pays a lot across many: the cost is quadratic in the
/// high-water mark, and Solidity never frees, so every abandoned array is
/// permanent. A verifier that reads from calldata and keeps nothing has a
/// mark of a few hundred words and this term disappears.
pub fn memory_gas(words: u64) -> u64 {
    3 * words + words * words / 512
}

/// The memory bill of a verifier holding `fixed` words before its query loop
/// and abandoning `per_query` words in each of `queries` iterations.
///
/// Expanded, this is `C(fixed) + q(3a + 2*fixed*a/512) + q^2 * a^2/512`, and
/// the last term is the failure mode: it makes gas quadratic in query count
/// for work that is linear in it. With `per_query` zero the whole thing
/// collapses to a constant, which is the shape a streaming verifier has and
/// the thing worth measuring.
pub fn memory_gas_over_queries(fixed: u64, per_query: u64, queries: u64) -> u64 {
    memory_gas(fixed + per_query * queries)
}
