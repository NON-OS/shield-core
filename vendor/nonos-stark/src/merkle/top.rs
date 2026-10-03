// NONOS Operating System (AGPL-3.0-or-later)

//! A tree's levels above a cut, for a tree whose leaves are a constant of the
//! circuit and cheap to recompute a few at a time.
//!
//! A prover opens a periodic tree at a handful of positions, and the tree is
//! the same for every proof. Keeping all of it costs every leaf; rebuilding it
//! costs every leaf's hash, every proof. Keeping the levels above `cut` costs
//! `2^-cut` of it, and each opening recomputes the `2^cut` leaves of its own
//! chunk and hashes them up to the stored level. The paths and the root are
//! the full tree's, so nothing downstream can tell the difference.

use super::hash::hash_node;
use super::tree::MerkleTree;
use alloc::vec::Vec;

const MAGIC: [u8; 4] = *b"NXTT";

pub struct TreeTop {
    cut: usize,
    /// The full tree's levels from `cut` up to the root.
    layers: Vec<Vec<[u8; 32]>>,
}

impl TreeTop {
    /// The levels of `tree` from `cut` up. `None` when the tree is not that tall.
    pub fn of(tree: &MerkleTree, cut: usize) -> Option<TreeTop> {
        let all = tree.layers();
        if cut >= all.len() {
            return None;
        }
        Some(TreeTop { cut, layers: all[cut..].to_vec() })
    }

    pub fn root(&self) -> [u8; 32] {
        self.layers.last().and_then(|l| l.first()).copied().unwrap_or([0u8; 32])
    }

    /// Leaves of the full tree.
    pub fn leaves(&self) -> usize {
        self.layers.first().map(Vec::len).unwrap_or(0) << self.cut
    }

    /// Leaves per chunk: what an opening recomputes.
    pub fn chunk(&self) -> usize {
        1usize << self.cut
    }

    /// The full tree's path for `index`, from `chunk`, the leaf digests of the
    /// `2^cut` leaves starting at `index` rounded down to a chunk. Empty when
    /// the chunk does not hash to the stored node above it: a stale cache or a
    /// wrong chunk opens nothing rather than a path to some other root.
    pub fn open(&self, index: usize, chunk: &[[u8; 32]]) -> Vec<[u8; 32]> {
        if chunk.len() != self.chunk() || index >= self.leaves() {
            return Vec::new();
        }
        let mut path = Vec::with_capacity(self.cut + self.layers.len());
        let mut level = chunk.to_vec();
        let mut idx = index & (self.chunk() - 1);
        for _ in 0..self.cut {
            path.push(level[idx ^ 1]);
            level = (0..level.len() / 2).map(|i| hash_node(&level[2 * i], &level[2 * i + 1])).collect();
            idx >>= 1;
        }
        let mut idx = index >> self.cut;
        if self.layers.first().and_then(|l| l.get(idx)) != level.first() {
            return Vec::new();
        }
        for layer in &self.layers {
            if layer.len() <= 1 {
                break;
            }
            path.push(layer[idx ^ 1]);
            idx >>= 1;
        }
        path
    }

    /// `NXTT`, the cut, the level count, then each level's length and digests.
    pub fn to_bytes(&self) -> Vec<u8> {
        let n: usize = self.layers.iter().map(Vec::len).sum();
        let mut b = Vec::with_capacity(12 + 4 * self.layers.len() + 32 * n);
        b.extend_from_slice(&MAGIC);
        b.extend_from_slice(&(self.cut as u32).to_le_bytes());
        b.extend_from_slice(&(self.layers.len() as u32).to_le_bytes());
        for layer in &self.layers {
            b.extend_from_slice(&(layer.len() as u32).to_le_bytes());
            for d in layer {
                b.extend_from_slice(d);
            }
        }
        b
    }

    /// The inverse of `to_bytes`, refusing anything not shaped like a tree:
    /// each level half the one below, ending at a single root, and every node
    /// the hash of its two children. A caller that checks the root then holds
    /// every stored level, not only the top one.
    pub fn from_bytes(b: &[u8]) -> Option<TreeTop> {
        let u32_at = |i: usize| -> Option<usize> {
            Some(u32::from_le_bytes(b.get(i..i + 4)?.try_into().ok()?) as usize)
        };
        if b.get(0..4)? != MAGIC {
            return None;
        }
        let cut = u32_at(4)?;
        let n_layers = u32_at(8)?;
        let mut at = 12;
        let mut layers = Vec::with_capacity(n_layers.min(64));
        for _ in 0..n_layers {
            let len = u32_at(at)?;
            at += 4;
            let bytes = b.get(at..at.checked_add(len.checked_mul(32)?)?)?;
            layers.push(bytes.as_chunks::<32>().0.to_vec());
            at += 32 * len;
        }
        let first = layers.first()?.len();
        if first == 0 || !first.is_power_of_two() || at != b.len() {
            return None;
        }
        let mut expect = first;
        for layer in &layers {
            if layer.len() != expect {
                return None;
            }
            expect /= 2;
        }
        if layers.last()?.len() != 1 || cut > 32 {
            return None;
        }
        /*
         * A damaged inner node under a correct root would load, and then
         * every opening through it would fail to verify, proof after proof.
         * Refused here instead, so the caller sees a bad cache and rebuilds.
         */
        for pair in layers.windows(2) {
            let (below, above) = (&pair[0], &pair[1]);
            for (i, node) in above.iter().enumerate() {
                if *node != hash_node(&below[2 * i], &below[2 * i + 1]) {
                    return None;
                }
            }
        }
        Some(TreeTop { cut, layers })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::Fp;

    /// Every path the top opens is the full tree's, and a top survives its
    /// bytes. A wrong chunk opens nothing.
    #[test]
    fn a_top_opens_the_full_trees_paths() {
        let leaves: Vec<Fp> = (0..256u64).map(|i| Fp::from_u64(i * 7919 + 3)).collect();
        let tree = MerkleTree::commit(&leaves);
        let top = TreeTop::from_bytes(&TreeTop::of(&tree, 3).map(|t| t.to_bytes()).unwrap_or_default());
        let Some(top) = top else { panic!("the top does not survive its bytes") };
        assert_eq!(top.root(), tree.root());
        let digests = &tree.layers()[0];
        for index in [0usize, 5, 8, 127, 255] {
            let base = index & !(top.chunk() - 1);
            assert_eq!(top.open(index, &digests[base..base + top.chunk()]), tree.open(index), "path {index}");
        }
        let wrong = &digests[8..16];
        assert!(top.open(0, wrong).is_empty(), "a chunk from elsewhere opened a path");
    }

    /// A byte flipped in any stored level is refused, though the root bytes
    /// are untouched.
    #[test]
    fn a_damaged_inner_level_is_refused() {
        let leaves: Vec<Fp> = (0..256u64).map(|i| Fp::from_u64(i * 7919 + 3)).collect();
        let tree = MerkleTree::commit(&leaves);
        let bytes = TreeTop::of(&tree, 3).map(|t| t.to_bytes()).unwrap_or_default();
        assert!(TreeTop::from_bytes(&bytes).is_some());
        /* level 0 digest 5, then level 1 digest 2: 12 header, 4 per length */
        for at in [12 + 4 + 32 * 5 + 7, 12 + 4 + 32 * 32 + 4 + 32 * 2] {
            let mut bad = bytes.clone();
            bad[at] ^= 1;
            assert!(TreeTop::from_bytes(&bad).is_none(), "byte {at} flipped and loaded");
        }
    }
}
