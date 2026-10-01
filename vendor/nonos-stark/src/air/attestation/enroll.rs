// NONOS Operating System (AGPL-3.0-or-later)

//! Enrolling a set of capsule or kernel images into the policy root a spawn gate
//! trusts. Each image is measured to a leaf and the leaves are committed to a
//! Poseidon Merkle tree; the root is the value the kernel bakes and gates against.
//! This is what an enrollment tool computes and what the boot chain carries.

use super::super::super::field::Fp;
use super::super::super::poseidon_merkle::PoseidonMerkleTree;
use super::measure::measure_capsule;
use super::super::poseidon::{Poseidon, RATE};
use alloc::vec::Vec;

/// The policy root over `images`: measure each to a leaf, then commit the leaves.
pub fn enroll_policy_root(hasher: &Poseidon, images: &[&[u8]]) -> [Fp; RATE] {
    let leaves: Vec<[Fp; RATE]> = images.iter().map(|img| measure_capsule(hasher, img)).collect();
    PoseidonMerkleTree::commit(hasher, &leaves).root()
}
