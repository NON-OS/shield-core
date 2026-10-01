// NONOS Operating System (AGPL-3.0-or-later)
//! The attestation statement: one slot of a 256-slot policy or boot tree.
//!
//! "Under root R, the leaf of context digest D with kind K is a slot." The
//! leaf is the kernel's v3 leaf (`nonos_attest_path::leaf_of`),
//! `compress([NONOSLV3, d0, d1, d2], [d3, K, 0, 0])`, and the tree is the note
//! tree's construction over the same Poseidon, depth 8.
//!
//! | words | content |
//! |---|---|
//! | 0 to 3 | R, the tree's root |
//! | 4 to 7 | D, the context digest's four little-endian words, each reduced |
//! | 8 | K: 0 kernel, 1 capsule, 3 bootloader |
//!
//! The gate computes all nine itself: R is the root it was built with, D the
//! digest of the context it is about to run (measurement, capability word,
//! epoch), K what it is loading. Nothing in a proof names them. A slot's
//! position and its siblings are private, and the proof is blinded, so a
//! verifier outside the machine learns that the slot exists and not where.
//!
//! One circuit serves all three kinds: the kind is a public word, wired to the
//! leaf's lane 5. Kind 2, padding, is never proven.

mod circuit;
mod native;
mod prove;
// The statement is proven on the v2 transcript only, format 7.
#[cfg(all(test, feature = "v2"))]
mod test;

pub use circuit::{shape, Witness};
pub use native::{fold, leaf, words_of, Statement};
pub use prove::{params, prove, prove_both, verify, Error, Point, POINTS};

/// "NONOSLV3", lane 0 of every leaf's first compression.
pub const LEAF_DOMAIN: u64 = 0x4E4F_4E4F_534C_5633;
pub const KIND_KERNEL: u64 = 0;
pub const KIND_CAPSULE: u64 = 1;
pub const KIND_PAD: u64 = 2;
pub const KIND_BOOTLOADER: u64 = 3;

/// Levels of the tree above the leaf: 256 slots.
pub const DEPTH: usize = 8;
/// Poseidon rounds per compression, as log2: the note tree's 32.
pub const LOG_ROUNDS: u32 = 5;
/// The statement's public words.
pub const WORDS: usize = 9;
pub const ROOT: usize = 0;
pub const DIGEST: usize = 4;
pub const KIND: usize = 8;

/// The trace every attestation proof has. The slot is about 340 rows; the
/// rest is padding, so FRI folds three times, the least the rank certificate
/// covers (`zk_rank::MIN_LAYERS`). At 2^13 this degree folds twice.
pub const LOG_TRACE: u32 = 14;
pub const PAD_LOG: u32 = 13;
pub const MASK_COLUMNS: usize = 2;
/// Rate 1/64 over the minimal domain, as every shipped point.
pub const EXTRA_BLOWUP_BITS: u32 = 5;
/// Fresh blinding draws before a proof without its certificate is given up.
pub const RANK_ATTEMPTS: usize = 3;
