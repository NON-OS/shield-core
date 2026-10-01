// NONOS Operating System (AGPL-3.0-or-later)

//! Parsing a money-grade proof from the bytes a capsule ships. It reads only from
//! untrusted input, validates every field element against the modulus, and returns
//! None on any malformed byte, so an attestation never panics on a hostile trailer.

use super::super::super::field::{Fp, Fp2, P};
use super::super::super::fri_ext::{FriProofExt, LayerOpeningExt, QueryProofExt};
use super::super::super::merkle::DIGEST_BYTES;
use super::types_ext::{StarkProofExt, StarkQueryExt};
use alloc::vec::Vec;

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.i.checked_add(n)?;
        if end > self.b.len() {
            return None;
        }
        let s = &self.b[self.i..end];
        self.i = end;
        Some(s)
    }
    /// Bytes still unread. A length field is capped at this, since every element
    /// consumes at least one byte, so a hostile count can never over-allocate.
    fn remaining(&self) -> usize {
        self.b.len() - self.i
    }
    fn u32(&mut self) -> Option<usize> {
        let b = self.take(4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
    }
    fn u64(&mut self) -> Option<u64> {
        let b = self.take(8)?;
        Some(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }
    fn fp(&mut self) -> Option<Fp> {
        let v = self.u64()?;
        (v < P).then(|| Fp::from_u64(v))
    }
    fn fp2(&mut self) -> Option<Fp2> {
        Some(Fp2 { c0: self.fp()?, c1: self.fp()? })
    }
    /// The kept bytes off the wire, the tail zero, as the hasher makes them.
    fn digest(&mut self) -> Option<[u8; 32]> {
        let mut d = [0u8; 32];
        d[..DIGEST_BYTES].copy_from_slice(self.take(DIGEST_BYTES)?);
        Some(d)
    }
    fn path(&mut self) -> Option<Vec<[u8; 32]>> {
        let n = self.u32()?;
        let mut v = Vec::with_capacity(n.min(self.remaining()));
        for _ in 0..n {
            v.push(self.digest()?);
        }
        Some(v)
    }
    fn fp2s(&mut self) -> Option<Vec<Fp2>> {
        let n = self.u32()?;
        let mut v = Vec::with_capacity(n.min(self.remaining()));
        for _ in 0..n {
            v.push(self.fp2()?);
        }
        Some(v)
    }
}

/// Parse a money-grade proof, or None on any malformed input.
///
/// This is the base half of an artifact and a sidecar follows it, so it
/// cannot demand that the input is exhausted. `deserialize_rounds` is the
/// parser for a complete shipped file and that one does.
pub fn deserialize_proof_ext(bytes: &[u8]) -> Option<StarkProofExt> {
    let mut r = Reader { b: bytes, i: 0 };
    let p = read_proof(&mut r, 0, 0)?;
    Some(p)
}

/// The same, reporting where the base half ended, for a caller parsing the
/// sections that follow it.
pub fn deserialize_proof_ext_at(bytes: &[u8], from: usize) -> Option<(StarkProofExt, usize)> {
    deserialize_proof_ext_at_ground(bytes, from, 0)
}

/// The same, for a proof whose FRI commit rounds are ground: `n_fold_nonces`
/// nonces follow the query proof-of-work nonce. The count is the parameter
/// set's, never the bytes'.
pub fn deserialize_proof_ext_at_ground(
    bytes: &[u8],
    from: usize,
    n_fold_nonces: usize,
) -> Option<(StarkProofExt, usize)> {
    deserialize_proof_ext_at_split(bytes, from, 0, n_fold_nonces)
}

/// The same, for a proof whose query grind is split as well: `n_pow_chain`
/// nonces follow the first query nonce, before the fold nonces. Both counts
/// are the parameter set's, never the bytes'.
pub fn deserialize_proof_ext_at_split(
    bytes: &[u8],
    from: usize,
    n_pow_chain: usize,
    n_fold_nonces: usize,
) -> Option<(StarkProofExt, usize)> {
    let mut r = Reader { b: bytes, i: from };
    let p = read_proof(&mut r, n_pow_chain, n_fold_nonces)?;
    Some((p, r.i))
}

fn read_proof(r: &mut Reader<'_>, n_pow_chain: usize, n_fold_nonces: usize) -> Option<StarkProofExt> {
    let trace_root = r.digest()?;
    let comp_root = r.digest()?;
    let ood_frame = r.fp2s()?;

    let nroots = r.u32()?;
    let mut roots = Vec::with_capacity(nroots.min(r.remaining()));
    for _ in 0..nroots {
        roots.push(r.digest()?);
    }
    let final_layer = r.fp2s()?;
    let nfq = r.u32()?;
    let mut fri_queries = Vec::with_capacity(nfq.min(r.remaining()));
    for _ in 0..nfq {
        let nl = r.u32()?;
        let mut layers = Vec::with_capacity(nl.min(r.remaining()));
        for _ in 0..nl {
            let mut v = [Fp2 { c0: Fp::ZERO, c1: Fp::ZERO }; crate::fri::FOLD];
            for slot in v.iter_mut() {
                *slot = r.fp2()?;
            }
            let path = r.path()?;
            layers.push(LayerOpeningExt { v, path });
        }
        fri_queries.push(QueryProofExt { layers });
    }
    let pow_nonce = r.u64()?;
    let mut pow_chain = Vec::with_capacity(n_pow_chain);
    for _ in 0..n_pow_chain {
        pow_chain.push(r.u64()?);
    }
    let mut fold_nonces = Vec::with_capacity(n_fold_nonces);
    for _ in 0..n_fold_nonces {
        fold_nonces.push(r.u64()?);
    }
    let fri = FriProofExt { roots, final_layer, queries: fri_queries, pow_nonce, pow_chain, fold_nonces };

    let nq = r.u32()?;
    let mut queries = Vec::with_capacity(nq.min(r.remaining()));
    for _ in 0..nq {
        let nt = r.u32()?;
        let mut trace = Vec::with_capacity(nt.min(r.remaining()));
        for _ in 0..nt {
            trace.push(r.fp()?);
        }
        let trace_path = r.path()?;
        let comp = r.fp2()?;
        let comp_path = r.path()?;
        queries.push(StarkQueryExt { trace, trace_path, comp, comp_path });
    }

    Some(StarkProofExt { trace_root, comp_root, ood_frame, fri, queries })
}
