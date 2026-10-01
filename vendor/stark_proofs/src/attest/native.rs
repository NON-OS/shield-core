// NONOS Operating System (AGPL-3.0-or-later)
//! The statement outside the circuit: the leaf and the fold a gate computes,
//! and the nine public words.

use super::{DEPTH, DIGEST, KIND, KIND_BOOTLOADER, KIND_CAPSULE, KIND_KERNEL, LEAF_DOMAIN, ROOT, WORDS};
use crate::crypto::stark::air::{Poseidon, RATE};
use crate::crypto::stark::field::Fp;
use alloc::vec::Vec;

pub(super) fn hasher() -> Poseidon {
    Poseidon::new(super::LOG_ROUNDS, [Fp::ZERO; RATE])
}

/// A 32-byte digest as four little-endian words, each reduced, as the gate
/// reads it.
pub fn words_of(d: &[u8; 32]) -> [Fp; RATE] {
    core::array::from_fn(|i| {
        let mut w = [0u8; 8];
        w.copy_from_slice(&d[8 * i..8 * i + 8]);
        Fp::from_u64(u64::from_le_bytes(w))
    })
}

/// A slot's leaf: `nonos_attest_path::leaf_of`, as the one compression the
/// circuit walks first.
pub fn leaf(kind: u64, d: &[u8; 32]) -> [Fp; RATE] {
    let w = words_of(d);
    hasher().compress(
        &[Fp::from_u64(LEAF_DOMAIN), w[0], w[1], w[2]],
        &[w[3], Fp::from_u64(kind), Fp::ZERO, Fp::ZERO],
    )
}

/// The root a leaf reaches along `siblings`, `right[i]` true when the node is
/// the right child at level `i`.
pub fn fold(start: [Fp; RATE], siblings: &[[Fp; RATE]], right: &[bool]) -> [Fp; RATE] {
    let h = hasher();
    siblings.iter().zip(right).fold(start, |node, (sib, &r)| {
        if r {
            h.compress(sib, &node)
        } else {
            h.compress(&node, sib)
        }
    })
}

/// What a gate checks: a root, a context digest, a kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Statement {
    pub root: [Fp; RATE],
    pub digest: [u8; 32],
    pub kind: u64,
}

impl Statement {
    /// `None` for a kind that is never proven: padding, or anything else.
    pub fn new(root: [Fp; RATE], digest: [u8; 32], kind: u64) -> Option<Statement> {
        matches!(kind, KIND_KERNEL | KIND_CAPSULE | KIND_BOOTLOADER).then_some(Statement { root, digest, kind })
    }

    /// The nine public words, in the order the circuit pins them.
    pub fn words(&self) -> Vec<Fp> {
        let mut w = alloc::vec![Fp::ZERO; WORDS];
        w[ROOT..ROOT + RATE].copy_from_slice(&self.root);
        w[DIGEST..DIGEST + RATE].copy_from_slice(&words_of(&self.digest));
        w[KIND] = Fp::from_u64(self.kind);
        w
    }

    /// Whether a slot at `siblings` and `right` holds this statement's leaf.
    pub fn holds(&self, siblings: &[[Fp; RATE]], right: &[bool]) -> bool {
        siblings.len() == DEPTH
            && right.len() == DEPTH
            && fold(leaf(self.kind, &self.digest), siblings, right) == self.root
    }
}
