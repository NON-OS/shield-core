// NONOS Operating System (AGPL-3.0-or-later)

//! Serializing a money-grade proof to the byte layout a chain verifier reads.
//! Little-endian throughout; a digest is its `DIGEST_BYTES` kept bytes.

use super::super::super::field::{Fp, Fp2};
use super::super::super::merkle::DIGEST_BYTES;
use super::types_ext::StarkProofExt;
use alloc::vec::Vec;

/// The proof as bytes: roots, out-of-domain frame, the FRI layers with their
/// authentication paths, and each consistency query with its wide-leaf trace path.
pub fn serialize_proof_ext(proof: &StarkProofExt) -> Vec<u8> {
    let mut b = Vec::new();
    digest(&mut b, &proof.trace_root);
    digest(&mut b, &proof.comp_root);
    u32le(&mut b, proof.ood_frame.len() as u32);
    for v in &proof.ood_frame {
        fp2(&mut b, *v);
    }
    u32le(&mut b, proof.fri.roots.len() as u32);
    for r in &proof.fri.roots {
        digest(&mut b, r);
    }
    u32le(&mut b, proof.fri.final_layer.len() as u32);
    for v in &proof.fri.final_layer {
        fp2(&mut b, *v);
    }
    u32le(&mut b, proof.fri.queries.len() as u32);
    for q in &proof.fri.queries {
        u32le(&mut b, q.layers.len() as u32);
        for l in &q.layers {
            for v in l.v {
                fp2(&mut b, v);
            }
            path(&mut b, &l.path);
        }
    }
    b.extend_from_slice(&proof.fri.pow_nonce.to_le_bytes());
    // The rest of a split query grind, in search order. None when it is one
    // search, so that encoding is byte for byte the one before the split.
    for nonce in &proof.fri.pow_chain {
        b.extend_from_slice(&nonce.to_le_bytes());
    }
    // The commit rounds' nonces, when they are ground. None otherwise, so an
    // encoding without them is byte for byte the one before them.
    for nonce in &proof.fri.fold_nonces {
        b.extend_from_slice(&nonce.to_le_bytes());
    }
    u32le(&mut b, proof.queries.len() as u32);
    for q in &proof.queries {
        u32le(&mut b, q.trace.len() as u32);
        for t in &q.trace {
            fp(&mut b, *t);
        }
        path(&mut b, &q.trace_path);
        fp2(&mut b, q.comp);
        path(&mut b, &q.comp_path);
    }
    b
}

fn u32le(b: &mut Vec<u8>, x: u32) {
    b.extend_from_slice(&x.to_le_bytes());
}
fn fp(b: &mut Vec<u8>, x: Fp) {
    b.extend_from_slice(&x.value().to_le_bytes());
}
fn fp2(b: &mut Vec<u8>, x: Fp2) {
    fp(b, x.c0);
    fp(b, x.c1);
}
fn digest(b: &mut Vec<u8>, d: &[u8; 32]) {
    b.extend_from_slice(&d[..DIGEST_BYTES]);
}
fn path(b: &mut Vec<u8>, p: &[[u8; 32]]) {
    u32le(b, p.len() as u32);
    for d in p {
        digest(b, d);
    }
}
