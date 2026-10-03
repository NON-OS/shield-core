// NONOS Operating System (AGPL-3.0-or-later)
//! The activity statement: "in week e, the holder of one nullifier key spent
//! k different notes whose nullifiers are leaves of the week's spend root Λ_e;
//! the week's tag is T and the reward goes to the owner digest P."
//!
//! | words | content |
//! |---|---|
//! | 0 to 3 | Λ_e, the week's nullifier root (depth 16, the note tree's construction) |
//! | 4 | e, the week |
//! | 5 | k, 1 to 4 |
//! | 6 to 9 | T, `compress([NOXACTV1, nk0, nk1, nk2], [nk3, e, 0, 0])` |
//! | 10 to 13 | P, the payout owner digest |
//! | 14 to 17 | K, the key commitment, `compress([NOXACTK1, nk0, nk1, nk2], [nk3, 0, 0, 0])` |
//!
//! Each of four slots recomputes a nullifier from the one key, `compress(
//! compress(nk, cm), [position, 0, 0, 0])`, with the live lane pinned to zero so
//! a dummy input's nullifier is never counted, and walks it to Λ_e. Live slots
//! come first and sit at strictly increasing positions of Λ_e, so k counts
//! different spends (`ActivityCount`). The key, the notes and the positions are
//! private; T is one per key per week and links no two weeks.
//!
//! K is the same for every week of one key. A holder registers it once with
//! the lock it belongs to, and a claim counts only for the lock that owns its
//! K, so a claim names the key that made it: selling one means handing over
//! the spending key, not a proof that names the buyer in P.

mod circuit;
mod native;
mod prove;
#[cfg(all(test, feature = "fri8"))]
mod test;

pub use circuit::{shape, Slot, Witness};
pub use native::{key_commitment, nullifier, tag, Statement};
pub use prove::{params, prove, prove_both, verify, Error, POINT};

/// "NOXACTV1", lane 0 of the tag's compression.
pub const ACTIVITY_DOMAIN: u64 = 0x4E4F_5841_4354_5631;
/// "NOXACTK1", lane 0 of the key commitment's compression.
pub const KEY_DOMAIN: u64 = 0x4E4F_5841_4354_4B31;
pub const SLOTS: usize = 4;
/// Levels of Λ_e.
pub const DEPTH: usize = 16;
pub const LOG_ROUNDS: u32 = 5;
pub const WORDS: usize = 18;
pub const LAMBDA: usize = 0;
pub const WEEK: usize = 4;
pub const COUNT: usize = 5;
pub const TAG: usize = 6;
pub const PAYOUT: usize = 10;
pub const KEY: usize = 14;
/// 2^13 rows, the transfer's length: with the same degree the FRI domain is
/// the transfer's 2^23, so every round's provable figure is the transfer's.
/// At 2^14 the two terms quadratic in the domain would each lose 2 bits.
pub const LOG_TRACE: u32 = 13;
pub const PAD_LOG: u32 = 12;
pub const MASK_COLUMNS: usize = 2;
/// Point A's rate, 2^-6: one home, in `shield_params::direct`.
pub use crate::shield_params::direct::EXTRA_BLOWUP_BITS;
pub const RANK_ATTEMPTS: usize = 3;
