// NONOS Operating System (AGPL-3.0-or-later)

//! The reading half, and every method returns `None` rather than panicking.
//!
//! A proof arrives from a relayer, a chain, or a file somebody else wrote. A
//! decoder that trusts a length prefix allocates whatever the sender asked for,
//! so every count is capped by the bytes actually left.

use crate::crypto::stark::air::RATE;
use crate::crypto::stark::field::{Fp, Fp2};
use alloc::vec::Vec;

pub(super) struct Reader<'a> {
    pub b: &'a [u8],
    pub i: usize,
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Reader<'a> {
        Reader { b, i: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.i.checked_add(n)?;
        let s = self.b.get(self.i..end)?;
        self.i = end;
        Some(s)
    }

    /// Bytes left, which is the only honest ceiling on a length prefix.
    fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.i)
    }

    pub fn u32(&mut self) -> Option<usize> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?) as usize)
    }

    pub fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    pub fn fp(&mut self) -> Option<Fp> {
        Some(Fp::from_u64(u64::from_le_bytes(
            self.take(8)?.try_into().ok()?,
        )))
    }

    pub fn fp2(&mut self) -> Option<Fp2> {
        Some(Fp2 {
            c0: self.fp()?,
            c1: self.fp()?,
        })
    }

    pub fn fps(&mut self) -> Option<Vec<Fp>> {
        let n = self.u32()?;
        let mut v = Vec::with_capacity(n.min(self.remaining() / 8));
        for _ in 0..n {
            v.push(self.fp()?);
        }
        Some(v)
    }

    pub fn fp2s(&mut self) -> Option<Vec<Fp2>> {
        let n = self.u32()?;
        let mut v = Vec::with_capacity(n.min(self.remaining() / 16));
        for _ in 0..n {
            v.push(self.fp2()?);
        }
        Some(v)
    }

    pub fn digest(&mut self) -> Option<[Fp; RATE]> {
        let mut d = [Fp::ZERO; RATE];
        for x in d.iter_mut() {
            *x = self.fp()?;
        }
        Some(d)
    }

    pub fn path(&mut self) -> Option<Vec<[Fp; RATE]>> {
        let n = self.u32()?;
        let mut v = Vec::with_capacity(n.min(self.remaining() / (8 * RATE)));
        for _ in 0..n {
            v.push(self.digest()?);
        }
        Some(v)
    }
}
