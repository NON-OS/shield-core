// NONOS Operating System (AGPL-3.0-or-later)

//! The Poseidon-transcript proof with its periodic sidecar, on the wire.
//!
//! This is the proof a wallet makes and a relayer carries. It had no wire form
//! at all: the recursion folded it in memory in the same process that produced
//! it, so nothing ever wrote one down, and a transfer that has never survived a
//! round trip is a transfer nobody can send.
//!
//! Field order follows the struct and nothing is packed, because the reader on
//! the other side of this is a Zig client and an on-chain decoder, not a
//! language runtime that agrees with Rust about layout.

use super::read::Reader;
use super::write::Writer;
use crate::crypto::stark::air::{
    PeriodicOpeningP, StarkProofExtP, StarkProofExtPPre, StarkQueryExtP,
};
use crate::crypto::stark::fri_poseidon_ext::{FriProofExtP, LayerOpeningExtP, QueryProofExtP};
use alloc::vec::Vec;

fn put_fri(w: &mut Writer, fri: &FriProofExtP) {
    w.u32(fri.roots.len());
    for r in &fri.roots {
        w.digest(r);
    }
    w.fp2s(&fri.final_layer);
    w.u32(fri.queries.len());
    for q in &fri.queries {
        w.u32(q.layers.len());
        for l in &q.layers {
            w.fp2(&l.a);
            w.fp2(&l.b);
            w.path(&l.path);
        }
    }
    w.u64(fri.pow_nonce);
}

fn get_fri(r: &mut Reader) -> Option<FriProofExtP> {
    let n = r.u32()?;
    let mut roots = Vec::with_capacity(n.min(1024));
    for _ in 0..n {
        roots.push(r.digest()?);
    }
    let final_layer = r.fp2s()?;
    let nq = r.u32()?;
    let mut queries = Vec::with_capacity(nq.min(4096));
    for _ in 0..nq {
        let nl = r.u32()?;
        let mut layers = Vec::with_capacity(nl.min(1024));
        for _ in 0..nl {
            let a = r.fp2()?;
            let b = r.fp2()?;
            let path = r.path()?;
            layers.push(LayerOpeningExtP { a, b, path });
        }
        queries.push(QueryProofExtP { layers });
    }
    let pow_nonce = r.u64()?;
    Some(FriProofExtP { roots, final_layer, queries, pow_nonce })
}

fn put_proof(w: &mut Writer, p: &StarkProofExtP) {
    w.digest(&p.trace_root);
    w.digest(&p.comp_root);
    w.fp2s(&p.ood_frame);
    put_fri(w, &p.fri);
    w.u32(p.queries.len());
    for q in &p.queries {
        w.fp2(&q.deep);
        w.fp2(&q.deep_sib);
        w.path(&q.deep_path);
        w.fps(&q.trace);
        w.path(&q.trace_path);
        w.fp2(&q.comp);
        w.fp2(&q.comp_sib);
        w.path(&q.comp_path);
    }
}

fn get_proof(r: &mut Reader) -> Option<StarkProofExtP> {
    let trace_root = r.digest()?;
    let comp_root = r.digest()?;
    let ood_frame = r.fp2s()?;
    let fri = get_fri(r)?;
    let nq = r.u32()?;
    let mut queries = Vec::with_capacity(nq.min(4096));
    for _ in 0..nq {
        let deep = r.fp2()?;
        let deep_sib = r.fp2()?;
        let deep_path = r.path()?;
        let trace = r.fps()?;
        let trace_path = r.path()?;
        let comp = r.fp2()?;
        let comp_sib = r.fp2()?;
        let comp_path = r.path()?;
        queries.push(StarkQueryExtP {
            deep,
            deep_sib,
            deep_path,
            trace,
            trace_path,
            comp,
            comp_sib,
            comp_path,
        });
    }
    Some(StarkProofExtP {
        trace_root,
        comp_root,
        ood_frame,
        fri,
        queries,
    })
}

/// The one round Poseidon form: the proof, then the periodic sidecar.
pub fn serialize_p_pre(pre: &StarkProofExtPPre) -> Vec<u8> {
    let mut w = Writer::new();
    put_proof(&mut w, &pre.proof);
    w.fp2s(&pre.periodic_z);
    w.u32(pre.openings.len());
    for op in &pre.openings {
        w.fps(&op.row);
        w.path(&op.path);
    }
    w.b
}

pub fn deserialize_p_pre(bytes: &[u8]) -> Option<StarkProofExtPPre> {
    let mut r = Reader::new(bytes);
    let pre = read_p_pre(&mut r)?;
    Some(pre)
}

pub(super) fn read_p_pre(r: &mut Reader) -> Option<StarkProofExtPPre> {
    let proof = get_proof(r)?;
    let periodic_z = r.fp2s()?;
    let n = r.u32()?;
    let mut openings = Vec::with_capacity(n.min(4096));
    for _ in 0..n {
        let row = r.fps()?;
        let path = r.path()?;
        openings.push(PeriodicOpeningP { row, path });
    }
    Some(StarkProofExtPPre {
        proof,
        periodic_z,
        openings,
    })
}
