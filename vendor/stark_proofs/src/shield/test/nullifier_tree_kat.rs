// NONOS Operating System (AGPL-3.0-or-later)
//! The weekly spend tree the activity statement proves membership in: a
//! depth-16 tree over a week's `NullifierSpent` digests, in chain order, built
//! the way the note tree is (zero leaves, `z[i+1] = compress(z[i], z[i])`,
//! each node `compress(left, right)`).
//!
//! The known answer is the production pool's first spends, both from one
//! settlement on Sepolia, block 11,817,581. The pool's own hasher, called on
//! chain by the tree's builder, gave the root below. This rebuilds it with the
//! prover's Poseidon, so the builder that publishes the weekly root and the
//! circuit that proves against it agree on every hash.
#![cfg(test)]

use crate::crypto::stark::air::{Poseidon, RATE};
use crate::crypto::stark::field::Fp;
use crate::host::try_unpack_digest;
use crate::shield::member::PoolTree;
use crate::shield::note::POOL_LOG_ROUNDS;

const DEPTH: usize = 16;
const LEAVES: [&str; 2] = [
    "0xa6e5d8c464bd954f58528ebbaf8f7ed6cf781846549cb6cedd0755e34a6c061e",
    "0x1f5b46cdd516d24735bc4bc26662831484d2e388e5bd9e950389dba6eb6f36b1",
];
const ROOT: &str = "0xb7b2a4cfafbbd989e7b9b30184aa4547f91118ec1aa720b22ba2018818593173";

fn hasher() -> Poseidon {
    Poseidon::new(POOL_LOG_ROUNDS, [Fp::ZERO; RATE])
}

fn digest(hex: &str) -> [Fp; RATE] {
    try_unpack_digest(hex).expect("a canonical digest")
}

#[test]
fn the_weekly_spend_tree_matches_the_pools_hasher() {
    let mut tree = PoolTree::with_depth(hasher(), DEPTH);
    for leaf in LEAVES {
        tree.insert(digest(leaf));
    }
    assert_eq!(
        tree.root(),
        digest(ROOT),
        "the prover's tree and the pool's hasher disagree"
    );
}

/// Each leaf's sixteen-step path, walked with the compression alone, reaches
/// the same root: the circuit's membership walk and the builder agree on the
/// order of every pair, not only on the final hash.
#[test]
fn each_leaf_walks_to_the_root() {
    let h = hasher();
    let mut tree = PoolTree::with_depth(h.clone(), DEPTH);
    for leaf in LEAVES {
        tree.insert(digest(leaf));
    }
    for (i, leaf) in LEAVES.iter().enumerate() {
        let (siblings, right) = tree.path(i);
        assert_eq!(siblings.len(), DEPTH);
        let mut node = digest(leaf);
        for (sib, is_right) in siblings.iter().zip(right) {
            node = if is_right {
                h.compress(sib, &node)
            } else {
                h.compress(&node, sib)
            };
        }
        assert_eq!(node, digest(ROOT), "leaf {i} does not walk to the root");
    }
}

/// The larger known answer: every spend of the launch pool between blocks
/// 11,680,381 and 11,820,380, 170 nullifiers, folded at depth 16. The leaves
/// were read from the chain with one provider and the root computed with the
/// pool's hasher by the tree's builder; this folds them with the prover's
/// Poseidon. 170 leaves reach the frontier and the zero subtrees at every
/// level, which two leaves do not.
#[test]
fn the_launch_pools_170_spends_fold_to_the_published_root() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../spec/d9/launch-170.json");
    let text = std::fs::read_to_string(path).expect("spec/d9/launch-170.json");
    let at = text.find("\"nullifiers\"").expect("the nullifier list");
    let leaves: Vec<&str> = text[at..]
        .split('"')
        .filter(|t| t.starts_with("0x") && t.len() == 66)
        .collect();
    assert_eq!(leaves.len(), 170);
    let root_at = text.find("\"root\": \"").expect("the root") + 9;
    let root = &text[root_at..root_at + 66];

    let mut tree = PoolTree::with_depth(hasher(), DEPTH);
    for leaf in &leaves {
        tree.insert(digest(leaf));
    }
    assert_eq!(
        tree.root(),
        digest(root),
        "the prover's tree and the pool's hasher disagree at 170 leaves"
    );
}
