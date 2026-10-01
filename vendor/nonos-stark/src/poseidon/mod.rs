// NONOS Operating System (AGPL-3.0-or-later)

//! Poseidon over Goldilocks: the permutation, its published parameters, and a
//! field sponge hash built on it. Used as the algebraic hash inside STARK
//! constraints, where an arithmetic-friendly permutation lets a proof reason
//! about hashing without a bit-level circuit.

pub mod constants;
pub mod permutation;
pub mod sponge;

pub use constants::{FULL_ROUNDS, N_ROUNDS, PARTIAL_ROUNDS, WIDTH};
pub use permutation::permute;
pub use sponge::{compress, hash, DIGEST, RATE};
