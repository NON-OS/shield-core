// NONOS Operating System (AGPL-3.0-or-later)
//! keccak256 for the Fiat-Shamir transcript and the Merkle commitment, blake3
//! for the image measurement.

mod constants;
mod digest;
mod keccak;
#[cfg(all(target_arch = "aarch64", any(feature = "parallel", test)))]
pub(crate) mod keccak_arm;

pub use digest::{blake3_hash, keccak256};
pub(crate) use keccak::{pow_lane, pow_template, Keccak};
