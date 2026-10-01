// NONOS Operating System (AGPL-3.0-or-later)
//! Format 6: a two round proof with its Merkle paths shared.
//!
//! The values are format 5's, in format 5's order, with every path taken out;
//! the paths follow at the end as one sibling stream per tree
//! (`merkle::multi`, `air::shared_paths`). Little endian throughout, a digest
//! is its `DIGEST_BYTES` kept bytes, a field element is refused at or above the
//! modulus, and nothing may follow the last stream.
//!
//! ```text
//! header                      40   magic, format 6, protocol, params id
//! perm_root                   D
//! region_width                4
//! trace_root, comp_root       2D
//! n_ood, ood_frame            4 + 16 n_ood
//! n_layers, fri roots         4 + D n_layers
//! n_final, final layer        4 + 16 n_final
//! n_q                         4
//! per query, per layer        64            the fold group's four values
//! pow_nonce, pow_chain        8 + 8 (chunks - 1)
//! fold_nonces                 8 n_layers when the commit rounds are ground
//! row_width                   4
//! per query                   8 row_width + 16   the row, the composition value
//! n_periodic, claims at z     4 + 16 n_periodic
//! per query                   8 n_periodic       the periodic row
//! per FRI layer, then trace,  4 + D count        each tree's stream
//!   perm, comp, periodic
//! ```
//!
//! A stream's count is on the wire so the body parses without the
//! transcript. It is not trusted: the verifier derives how many siblings the
//! positions need and refuses a stream of any other length.

use crate::crypto::stark::air::{
    PeriodicOpeningExt, SharedPaths, StarkProofExt, StarkProofExtPre, StarkProofExtRounds,
    StarkQueryExt,
};
use crate::crypto::stark::field::{Fp, Fp2, P};
use crate::crypto::stark::fri::FOLD;
use crate::crypto::stark::fri_ext::{FriProofExt, LayerOpeningExt, QueryProofExt};
use crate::crypto::stark::merkle::DIGEST_BYTES;
use crate::proof_wire::header::{
    check_header_as, write_header_as, ParamSet, FORMAT_SHARED_BUILD, HEADER_BYTES,
};
use alloc::vec::Vec;

/// The encoding of `rounds` with `shared` in place of its paths. The paths in
/// `rounds` are not read.
pub fn serialize_rounds_shared(
    rounds: &StarkProofExtRounds,
    shared: &SharedPaths,
    params: &ParamSet,
) -> Vec<u8> {
    let proof = &rounds.pre.proof;
    let mut b = write_header_as(params, FORMAT_SHARED_BUILD);
    digest(&mut b, &rounds.perm_root);
    u32le(&mut b, rounds.region_width);
    digest(&mut b, &proof.trace_root);
    digest(&mut b, &proof.comp_root);
    u32le(&mut b, proof.ood_frame.len());
    for v in &proof.ood_frame {
        fp2(&mut b, v);
    }
    u32le(&mut b, proof.fri.roots.len());
    for r in &proof.fri.roots {
        digest(&mut b, r);
    }
    u32le(&mut b, proof.fri.final_layer.len());
    for v in &proof.fri.final_layer {
        fp2(&mut b, v);
    }
    u32le(&mut b, proof.fri.queries.len());
    for q in &proof.fri.queries {
        for l in &q.layers {
            for v in &l.v {
                fp2(&mut b, v);
            }
        }
    }
    b.extend_from_slice(&proof.fri.pow_nonce.to_le_bytes());
    for n in proof.fri.pow_chain.iter().chain(&proof.fri.fold_nonces) {
        b.extend_from_slice(&n.to_le_bytes());
    }
    u32le(&mut b, proof.queries.first().map_or(0, |q| q.trace.len()));
    for q in &proof.queries {
        for t in &q.trace {
            fp(&mut b, t);
        }
        fp2(&mut b, &q.comp);
    }
    u32le(&mut b, rounds.pre.periodic_z.len());
    for v in &rounds.pre.periodic_z {
        fp2(&mut b, v);
    }
    // Format 7: the DEEP nonce, where the transcript absorbs it.
    #[cfg(feature = "v2")]
    b.extend_from_slice(&rounds.pre.deep_nonce.to_le_bytes());
    for op in &rounds.pre.openings {
        for v in &op.row {
            fp(&mut b, v);
        }
    }
    for s in shared
        .fri
        .iter()
        .chain([&shared.trace, &shared.perm, &shared.comp, &shared.periodic])
    {
        u32le(&mut b, s.len());
        for d in s {
            digest(&mut b, d);
        }
    }
    b
}

/// Parse a format 6 artifact into the proof without its paths and the
/// streams that stand for them. Refuses a header that is not format 6 at
/// `expect`, a row of the wrong width, a non canonical element, and any byte
/// after the last stream. The skeleton's paths are empty, one per query, so
/// only `stark_verify_ext_rounds_shared_why` can make anything of it.
pub fn deserialize_rounds_shared(
    bytes: &[u8],
    expect: &ParamSet,
) -> Option<(StarkProofExtRounds, SharedPaths)> {
    check_header_as(bytes, expect, FORMAT_SHARED_BUILD)?;
    let mut r = Reader {
        b: bytes,
        i: HEADER_BYTES,
    };
    let perm_root = r.digest()?;
    let region_width = r.u32()?;
    let trace_root = r.digest()?;
    let comp_root = r.digest()?;
    let ood_frame = r.fp2s()?;
    let n_layers = r.count(DIGEST_BYTES)?;
    let mut roots = Vec::with_capacity(n_layers);
    for _ in 0..n_layers {
        roots.push(r.digest()?);
    }
    let final_layer = r.fp2s()?;
    let n_q = r.count(16 * FOLD * n_layers.max(1))?;
    let mut fri_queries = Vec::with_capacity(n_q);
    for _ in 0..n_q {
        let mut layers = Vec::with_capacity(n_layers);
        for _ in 0..n_layers {
            let mut v = [Fp2::ZERO; FOLD];
            for slot in v.iter_mut() {
                *slot = r.fp2()?;
            }
            layers.push(LayerOpeningExt {
                v,
                path: Vec::new(),
            });
        }
        fri_queries.push(QueryProofExt { layers });
    }
    let pow_nonce = r.u64()?;
    let chain = expect.grind_chunks.max(1) as usize - 1;
    let pow_chain = (0..chain).map(|_| r.u64()).collect::<Option<Vec<u64>>>()?;
    let folds = if expect.commit_grind_bits != 0 {
        n_layers
    } else {
        0
    };
    let fold_nonces = (0..folds).map(|_| r.u64()).collect::<Option<Vec<u64>>>()?;

    let row_width = r.u32()?;
    if row_width != expect.trace_width as usize || row_width <= region_width {
        return None;
    }
    if n_q.checked_mul(8 * row_width + 16)? > r.remaining() {
        return None;
    }
    let mut queries = Vec::with_capacity(n_q);
    for _ in 0..n_q {
        let trace = (0..row_width)
            .map(|_| r.fp())
            .collect::<Option<Vec<Fp>>>()?;
        let comp = r.fp2()?;
        queries.push(StarkQueryExt {
            trace,
            trace_path: Vec::new(),
            comp,
            comp_path: Vec::new(),
        });
    }
    let periodic_z = r.fp2s()?;
    #[cfg(feature = "v2")]
    let deep_nonce = r.u64()?;
    #[cfg(not(feature = "v2"))]
    let deep_nonce = 0u64;
    let n_periodic = periodic_z.len();
    if n_q.checked_mul(8 * n_periodic)? > r.remaining() {
        return None;
    }
    let mut openings = Vec::with_capacity(n_q);
    for _ in 0..n_q {
        let row = (0..n_periodic)
            .map(|_| r.fp())
            .collect::<Option<Vec<Fp>>>()?;
        openings.push(PeriodicOpeningExt {
            row,
            path: Vec::new(),
        });
    }

    let mut fri = Vec::with_capacity(n_layers);
    for _ in 0..n_layers {
        fri.push(r.stream()?);
    }
    let shared = SharedPaths {
        fri,
        trace: r.stream()?,
        perm: r.stream()?,
        comp: r.stream()?,
        periodic: r.stream()?,
    };
    if r.remaining() != 0 {
        return None;
    }

    let proof = StarkProofExt {
        trace_root,
        comp_root,
        ood_frame,
        fri: FriProofExt {
            roots,
            final_layer,
            queries: fri_queries,
            pow_nonce,
            pow_chain,
            fold_nonces,
        },
        queries,
    };
    let skeleton = StarkProofExtRounds {
        pre: StarkProofExtPre {
            deep_nonce,
            proof,
            periodic_z,
            openings,
        },
        perm_root,
        region_width,
        perm_paths: alloc::vec![Vec::new(); n_q],
    };
    Some((skeleton, shared))
}

fn u32le(b: &mut Vec<u8>, x: usize) {
    b.extend_from_slice(&(x as u32).to_le_bytes());
}
fn fp(b: &mut Vec<u8>, x: &Fp) {
    b.extend_from_slice(&x.value().to_le_bytes());
}
fn fp2(b: &mut Vec<u8>, x: &Fp2) {
    fp(b, &x.c0);
    fp(b, &x.c1);
}
fn digest(b: &mut Vec<u8>, d: &[u8; 32]) {
    b.extend_from_slice(&d[..DIGEST_BYTES]);
}

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

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    /// A count of items at least `each` bytes long, refused when the bytes
    /// left could not hold them: an allocation is never sized by a claim.
    fn count(&mut self, each: usize) -> Option<usize> {
        let n = self.u32()?;
        (n <= self.remaining() / each.max(1)).then_some(n)
    }

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

    fn fp2s(&mut self) -> Option<Vec<Fp2>> {
        let n = self.count(16)?;
        (0..n).map(|_| self.fp2()).collect()
    }

    fn digest(&mut self) -> Option<[u8; 32]> {
        let mut d = [0u8; 32];
        d[..DIGEST_BYTES].copy_from_slice(self.take(DIGEST_BYTES)?);
        Some(d)
    }

    fn stream(&mut self) -> Option<Vec<[u8; 32]>> {
        let n = self.count(DIGEST_BYTES)?;
        (0..n).map(|_| self.digest()).collect()
    }
}
