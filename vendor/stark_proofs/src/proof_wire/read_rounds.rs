// NONOS Operating System (AGPL-3.0-or-later)
//! The inverse of `serialize_rounds`: a complete shipped artifact, parsed.
//!
//! There was no such parser. The encoder existed, the chain read the bytes in
//! Solidity, and nothing in Rust read a whole file back, so the reference
//! verifier could never be run over the exact bytes a settler broadcasts and
//! there was no oracle to hold a ported verifier to. Every check here is a
//! check the chain's reader must also make, and a disagreement between the
//! two is a disagreement about what a valid proof is.
//!
//! Strict by construction. A count that disagrees with a count the proof
//! already carries is refused rather than reconciled, a field element at or
//! above the modulus is refused, and **bytes after the last section are
//! refused**: a proof with two encodings has two digests, and a settlement
//! that identifies a proof by its hash then has two names for one object.

use crate::crypto::stark::air::{
    deserialize_proof_ext_at_split, PeriodicOpeningExt, StarkProofExtPre, StarkProofExtRounds,
};
use crate::crypto::stark::field::{Fp, Fp2, P};
use crate::crypto::stark::merkle::DIGEST_BYTES;
use crate::proof_wire::header::{check_header, ParamSet, HEADER_BYTES};
use alloc::vec::Vec;

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.i.checked_add(n)?;
        let s = self.b.get(self.i..end)?;
        self.i = end;
        Some(s)
    }

    fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.i)
    }

    fn u32(&mut self) -> Option<usize> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?) as usize)
    }

    /// A field element, refused at or above the modulus: two encodings of one
    /// value is a transcript that hashes differently for the same statement.
    fn fp(&mut self) -> Option<Fp> {
        let v = u64::from_le_bytes(self.take(8)?.try_into().ok()?);
        (v < P).then(|| Fp::from_u64(v))
    }

    fn fp2(&mut self) -> Option<Fp2> {
        Some(Fp2 {
            c0: self.fp()?,
            c1: self.fp()?,
        })
    }

    /// The kept bytes of a digest, the tail zero, as the hasher makes them.
    fn digest(&mut self) -> Option<[u8; 32]> {
        let mut d = [0u8; 32];
        d[..DIGEST_BYTES].copy_from_slice(self.take(DIGEST_BYTES)?);
        Some(d)
    }

    fn path(&mut self) -> Option<Vec<[u8; 32]>> {
        let n = self.u32()?;
        if n > self.remaining() / DIGEST_BYTES {
            return None;
        }
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(self.digest()?);
        }
        Some(v)
    }
}

/// Parse a complete artifact, refusing anything this build does not serve.
///
/// Fail closed on identity before anything else is read: the magic, the
/// format this build decodes, the protocol whose statement it means, and the
/// parameter set the caller was generated for. A correctly decoded proof of
/// the right relation at the wrong soundness point is the failure the last
/// of those exists to stop, and it is the one a decoder cannot notice.
pub fn deserialize_rounds(bytes: &[u8], expect: &ParamSet) -> Option<StarkProofExtRounds> {
    check_header(bytes, expect)?;
    let fold_nonces = if expect.commit_grind_bits != 0 {
        crate::proof_wire::Layout::fri_shape(expect).0
    } else {
        0
    };
    let pow_chain = expect.grind_chunks.max(1) as usize - 1;
    read_body_split(bytes, HEADER_BYTES, pow_chain, fold_nonces)
}

/// The same body without a header, for an artifact produced before the
/// format described itself. Tooling and migration only: production
/// verification takes one unambiguous format, so this is not reachable from
/// `deserialize_rounds` and nothing auto-detects.
pub fn deserialize_rounds_legacy(bytes: &[u8]) -> Option<StarkProofExtRounds> {
    read_body_split(bytes, 0, 0, 0)
}

/// `n_queries` and the sidecar's width are the proof's own: the periodic
/// claim count is read once and every query's row is that long, and the
/// opening count is the query count rather than a second number on the wire.
fn read_body_split(
    bytes: &[u8],
    from: usize,
    pow_chain: usize,
    fold_nonces: usize,
) -> Option<StarkProofExtRounds> {
    let mut r = Reader { b: bytes, i: from };
    let perm_root = r.digest()?;
    let region_width = r.u32()?;

    let (proof, at) = deserialize_proof_ext_at_split(bytes, r.i, pow_chain, fold_nonces)?;
    r.i = at;

    let n_periodic = r.u32()?;
    if n_periodic > r.remaining() / 16 {
        return None;
    }
    let mut periodic_z = Vec::with_capacity(n_periodic);
    for _ in 0..n_periodic {
        periodic_z.push(r.fp2()?);
    }
    #[cfg(feature = "v2")]
    let deep_nonce = {
        let b = r.take(8)?;
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    };
    #[cfg(not(feature = "v2"))]
    let deep_nonce = 0u64;

    let n_q = proof.queries.len();
    let mut openings = Vec::with_capacity(n_q);
    for _ in 0..n_q {
        let mut row = Vec::with_capacity(n_periodic);
        for _ in 0..n_periodic {
            row.push(r.fp()?);
        }
        openings.push(PeriodicOpeningExt {
            row,
            path: r.path()?,
        });
    }

    let mut perm_paths = Vec::with_capacity(n_q);
    for _ in 0..n_q {
        perm_paths.push(r.path()?);
    }

    // Nothing may follow. A trailing byte does not change what the proof
    // says and does change what it hashes to, which is the difference
    // between a proof and its name.
    if r.remaining() != 0 {
        return None;
    }

    Some(StarkProofExtRounds {
        pre: StarkProofExtPre {
            proof,
            periodic_z,
            openings,
            deep_nonce,
        },
        perm_root,
        region_width,
        perm_paths,
    })
}
