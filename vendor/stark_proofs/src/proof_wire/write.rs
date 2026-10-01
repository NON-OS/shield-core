// NONOS Operating System (AGPL-3.0-or-later)

//! Field elements, digests and paths onto the wire.
//!
//! Little endian and length prefixed, the same convention the keccak codec
//! uses, so a reader of one is not surprised by the other.

use crate::crypto::stark::air::RATE;
use crate::crypto::stark::field::{Fp, Fp2};
use alloc::vec::Vec;

pub(super) struct Writer {
    pub b: Vec<u8>,
}

impl Writer {
    pub fn new() -> Writer {
        Writer { b: Vec::new() }
    }

    pub fn u32(&mut self, v: usize) {
        self.b.extend_from_slice(&(v as u32).to_le_bytes());
    }

    pub fn u64(&mut self, v: u64) {
        self.b.extend_from_slice(&v.to_le_bytes());
    }

    pub fn fp(&mut self, v: &Fp) {
        self.b.extend_from_slice(&v.value().to_le_bytes());
    }

    pub fn fp2(&mut self, v: &Fp2) {
        self.fp(&v.c0);
        self.fp(&v.c1);
    }

    pub fn fps(&mut self, v: &[Fp]) {
        self.u32(v.len());
        for x in v {
            self.fp(x);
        }
    }

    pub fn fp2s(&mut self, v: &[Fp2]) {
        self.u32(v.len());
        for x in v {
            self.fp2(x);
        }
    }

    pub fn digest(&mut self, d: &[Fp; RATE]) {
        for x in d {
            self.fp(x);
        }
    }

    /// A Merkle path: the depth, then that many digests. The depth travels
    /// because a verifier reading a batch of them cannot recover where one ends
    /// from the tree it has not yet walked.
    pub fn path(&mut self, p: &[[Fp; RATE]]) {
        self.u32(p.len());
        for d in p {
            self.digest(d);
        }
    }
}
