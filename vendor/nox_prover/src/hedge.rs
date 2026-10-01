// NONOS Operating System (AGPL-3.0-or-later)
//! Hedged randomness: the bytes every random value of a proof is drawn from.
//!
//! Every blinding in a proof, the output notes' and the columns', is drawn
//! from bytes the caller passes. If two spends were proved from the same bytes
//! their blindings would be equal, and the difference of their openings would
//! cancel them and hand back the difference of the witnesses. The prover cannot
//! tell fresh bytes from reused ones, so it does not rely on them alone.
//!
//! The stream is Keccak-256 in counter mode under a key that binds the caller's
//! entropy, the seed file and the request:
//!
//! ```text
//! key     = keccak256(DOMAIN || len(entropy) as u32 le || entropy
//!                     || keccak256(seed) || keccak256(request))
//! block i = keccak256(key || i as u32 le),  i = 0, 1, ...
//! stream  = the first ENTROPY_BYTES bytes of block 0 || block 1 || ...
//! ```
//!
//! In the random oracle model the stream is uniform to anyone who lacks either
//! the entropy or the seed file's secrets, so it is as good as fresh entropy
//! when the entropy is fresh, and still unpredictable when it is not. Two
//! spends that differ in their seed or their request get independent streams
//! whatever the entropy was. The same spend proved twice from the same bytes
//! gives the same proof, which reveals nothing new. The same construction
//! RFC 6979 applies to signature nonces.

use crate::proof::ENTROPY_BYTES;
use stark_proofs::crypto::stark::hash::keccak256;

/// The domain tag; a change to the construction changes it.
pub const DOMAIN: &[u8] = b"NOX-HEDGED-ENTROPY-1";

/// The stream a proof draws from. Refuses fewer than `ENTROPY_BYTES` bytes of
/// entropy: hedging makes reused bytes safe, not missing ones acceptable.
pub fn hedge(entropy: &[u8], seed: &str, request: &str) -> Result<Vec<u8>, String> {
    if entropy.len() < ENTROPY_BYTES {
        return Err(format!(
            "not enough entropy: {} bytes, pass at least {ENTROPY_BYTES} random bytes",
            entropy.len()
        ));
    }
    let len = u32::try_from(entropy.len()).map_err(|_| "entropy longer than 4 GiB".to_string())?;
    let mut k = Vec::with_capacity(DOMAIN.len() + 4 + entropy.len() + 64);
    k.extend_from_slice(DOMAIN);
    k.extend_from_slice(&len.to_le_bytes());
    k.extend_from_slice(entropy);
    k.extend_from_slice(&keccak256(seed.as_bytes()));
    k.extend_from_slice(&keccak256(request.as_bytes()));
    let key = keccak256(&k);

    let mut out = Vec::with_capacity(ENTROPY_BYTES + 32);
    let mut i = 0u32;
    while out.len() < ENTROPY_BYTES {
        let mut b = [0u8; 36];
        b[..32].copy_from_slice(&key);
        b[32..].copy_from_slice(&i.to_le_bytes());
        out.extend_from_slice(&keccak256(&b));
        i += 1;
    }
    out.truncate(ENTROPY_BYTES);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(b: u8) -> Vec<u8> {
        (0..ENTROPY_BYTES)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(b))
            .collect()
    }

    #[test]
    fn the_same_spend_gives_the_same_stream() {
        let a = hedge(&bytes(1), "seed", "request").unwrap();
        assert_eq!(a, hedge(&bytes(1), "seed", "request").unwrap());
        assert_eq!(a.len(), ENTROPY_BYTES);
    }

    /// The case the hedge exists for: reused entropy under two spends.
    #[test]
    fn reused_entropy_under_another_spend_gives_an_unrelated_stream() {
        let e = bytes(1);
        let a = hedge(&e, "seed", "request one").unwrap();
        let b = hedge(&e, "seed", "request two").unwrap();
        let c = hedge(&e, "another seed", "request one").unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
        // Unrelated, not merely unequal: no 8-byte word in common position.
        let same = a.chunks(8).zip(b.chunks(8)).filter(|(x, y)| x == y).count();
        assert_eq!(same, 0);
    }

    #[test]
    fn fresh_entropy_gives_a_fresh_stream() {
        assert_ne!(
            hedge(&bytes(1), "s", "r").unwrap(),
            hedge(&bytes(2), "s", "r").unwrap()
        );
    }

    /// A length prefix keeps entropy and seed from sliding into each other.
    #[test]
    fn longer_entropy_is_bound_by_its_length() {
        let mut long = bytes(1);
        long.push(7);
        assert_ne!(
            hedge(&bytes(1), "s", "r").unwrap(),
            hedge(&long, "s", "r").unwrap()
        );
    }

    #[test]
    fn short_entropy_is_refused() {
        assert!(hedge(&[0u8; ENTROPY_BYTES - 1], "s", "r").is_err());
    }
}
