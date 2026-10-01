// NONOS Operating System (AGPL-3.0-or-later)
//! The two digests the proof stack computes, carried in this crate so the
//! prover and the verifier agree whichever binary links them.

use super::keccak::Keccak;

/// Ethereum-style Keccak-256 (0x01 padding), the transcript and Merkle hash.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::new(512, 32, 0x01);
    hasher.update(data);
    hasher.finalize32()
}

/// BLAKE3, the image measurement hash. Matches the bootloader's kernel measure.
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}
