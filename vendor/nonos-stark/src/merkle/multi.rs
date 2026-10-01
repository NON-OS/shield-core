// NONOS Operating System (AGPL-3.0-or-later)

//! Shared authentication paths: one stream of siblings for a set of leaves in
//! one tree, in place of one full path per leaf.
//!
//! Two leaves whose paths meet share every node above the meeting point, and
//! a sibling that is itself an ancestor of an opened leaf is computed rather
//! than carried. The stream holds only what cannot be computed, in one order:
//!
//! - the opened indices, sorted and deduplicated;
//! - level by level from the leaves up, for each known node in ascending
//!   index, its sibling when that sibling is not also known;
//! - the known set of the next level is the parents of this one.
//!
//! Both sides derive that order from the indices alone, so the stream carries
//! no indices and no lengths of its own. `compress` builds it from full
//! paths, `expand` rebuilds the full paths from it, and a verifier then walks
//! each path exactly as before. `expand` refuses a stream that is short, long,
//! or disagrees with itself; it does not compare against a root, because the
//! per-leaf walks that follow do.

use super::hash::hash_node;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// The opened indices, sorted, once each.
fn known_leaves(indices: impl Iterator<Item = usize>) -> Vec<usize> {
    let mut v: Vec<usize> = indices.collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// The parents of a sorted level, sorted, once each.
fn parents(level: &[usize]) -> Vec<usize> {
    let mut v: Vec<usize> = level.iter().map(|i| i >> 1).collect();
    v.dedup();
    v
}

/// How many siblings the stream holds for `indices` in a tree of `depth`
/// levels. A reader bounds its allocation with it before reading a digest.
pub fn stream_len(depth: usize, indices: &[usize]) -> usize {
    let mut level = known_leaves(indices.iter().copied());
    let mut n = 0usize;
    for _ in 0..depth {
        n += level
            .iter()
            .filter(|&&i| level.binary_search(&(i ^ 1)).is_err())
            .count();
        level = parents(&level);
    }
    n
}

/// The stream for `openings`, each an opened index and its full path, from the
/// leaf's sibling up. `None` when a path is not `depth` long, an index does
/// not fit the tree, or two openings at one index disagree about a sibling.
pub fn compress(depth: usize, openings: &[(usize, &[[u8; 32]])]) -> Option<Vec<[u8; 32]>> {
    if depth >= usize::BITS as usize {
        return None;
    }
    for (i, path) in openings {
        if path.len() != depth || *i >> depth != 0 {
            return None;
        }
    }
    let mut level = known_leaves(openings.iter().map(|(i, _)| *i));
    let mut out = Vec::new();
    for l in 0..depth {
        for &node in &level {
            if level.binary_search(&(node ^ 1)).is_ok() {
                continue;
            }
            let mut sib: Option<[u8; 32]> = None;
            for (i, path) in openings {
                if i >> l == node {
                    match sib {
                        None => sib = Some(path[l]),
                        Some(s) if s != path[l] => return None,
                        Some(_) => {}
                    }
                }
            }
            out.push(sib?);
        }
        level = parents(&level);
    }
    Some(out)
}

/// What `expand` gives back: the root the stream implies, then each leaf's
/// full path in the order the leaves were given.
pub type Expanded = ([u8; 32], Vec<Vec<[u8; 32]>>);

/// The full path of every leaf in `leaves`, in the order given, and the root
/// the stream implies. `leaves` pairs each opened index with its leaf digest;
/// two leaves at one index must carry one digest.
///
/// `None` when an index does not fit the tree, two leaves at one index differ,
/// or the stream is not exactly as long as the indices say.
pub fn expand(depth: usize, leaves: &[(usize, [u8; 32])], stream: &[[u8; 32]]) -> Option<Expanded> {
    if depth >= usize::BITS as usize || leaves.is_empty() {
        return None;
    }
    let mut known: BTreeMap<usize, [u8; 32]> = BTreeMap::new();
    for &(i, d) in leaves {
        if i >> depth != 0 {
            return None;
        }
        if let Some(prev) = known.insert(i, d) {
            if prev != d {
                return None;
            }
        }
    }

    // Every node a path reads, per level: the known ones and the carried ones.
    let mut levels: Vec<BTreeMap<usize, [u8; 32]>> = Vec::with_capacity(depth);
    let mut next = 0usize;
    for _ in 0..depth {
        let mut all = known.clone();
        for &node in known.keys() {
            let sib = node ^ 1;
            if !known.contains_key(&sib) {
                all.insert(sib, *stream.get(next)?);
                next += 1;
            }
        }
        let mut up: BTreeMap<usize, [u8; 32]> = BTreeMap::new();
        for &node in known.keys() {
            let even = node & !1;
            if up.contains_key(&(node >> 1)) {
                continue;
            }
            let parent = hash_node(all.get(&even)?, all.get(&(even | 1))?);
            up.insert(node >> 1, parent);
        }
        levels.push(all);
        known = up;
    }
    if next != stream.len() || known.len() != 1 {
        return None;
    }
    let root = *known.get(&0)?;

    let paths = leaves
        .iter()
        .map(|&(i, _)| {
            (0..depth)
                .map(|l| levels[l].get(&((i >> l) ^ 1)).copied())
                .collect::<Option<Vec<[u8; 32]>>>()
        })
        .collect::<Option<Vec<_>>>()?;
    Some((root, paths))
}

#[cfg(test)]
mod tests {
    use super::super::tree::MerkleTree;
    use super::super::verify::verify_path_ext;
    use super::*;
    use crate::field::{Fp, Fp2};

    fn tree(depth: usize) -> (MerkleTree, Vec<Fp2>) {
        let leaves: Vec<Fp2> = (0..1u64 << depth)
            .map(|i| Fp2 {
                c0: Fp::from_u64(i * 7 + 1),
                c1: Fp::from_u64(i ^ 0x55),
            })
            .collect();
        (MerkleTree::commit_ext(&leaves), leaves)
    }

    fn roundtrip(depth: usize, idx: &[usize]) -> usize {
        let (t, vals) = tree(depth);
        let paths: Vec<Vec<[u8; 32]>> = idx.iter().map(|&i| t.open(i)).collect();
        let openings: Vec<(usize, &[[u8; 32]])> = idx
            .iter()
            .zip(&paths)
            .map(|(&i, p)| (i, p.as_slice()))
            .collect();
        let stream = compress(depth, &openings).expect("compress");
        assert_eq!(stream.len(), stream_len(depth, idx));
        let leaves: Vec<(usize, [u8; 32])> = idx
            .iter()
            .map(|&i| (i, super::super::hash_leaf_ext(vals[i])))
            .collect();
        let (root, back) = expand(depth, &leaves, &stream).expect("expand");
        assert_eq!(root, t.root());
        assert_eq!(back, paths);
        for (&i, p) in idx.iter().zip(&back) {
            assert!(verify_path_ext(&t.root(), i, vals[i], p));
        }
        stream.len()
    }

    #[test]
    fn one_leaf_is_its_own_path() {
        assert_eq!(roundtrip(6, &[37]), 6);
    }

    #[test]
    fn siblings_share_everything_above_them() {
        // 10 and 11 are siblings: nothing at level 0, one node a level above.
        assert_eq!(roundtrip(5, &[10, 11]), 4);
    }

    #[test]
    fn repeated_and_unsorted_indices_round_trip() {
        roundtrip(7, &[90, 3, 90, 64, 2, 127, 0]);
    }

    #[test]
    fn every_leaf_needs_no_stream() {
        let all: Vec<usize> = (0..16).collect();
        assert_eq!(roundtrip(4, &all), 0);
    }

    #[test]
    fn a_short_long_or_altered_stream_is_refused() {
        let depth = 8;
        let idx = [5usize, 200, 201, 77];
        let (t, vals) = tree(depth);
        let paths: Vec<Vec<[u8; 32]>> = idx.iter().map(|&i| t.open(i)).collect();
        let openings: Vec<(usize, &[[u8; 32]])> = idx
            .iter()
            .zip(&paths)
            .map(|(&i, p)| (i, p.as_slice()))
            .collect();
        let stream = compress(depth, &openings).unwrap();
        let leaves: Vec<(usize, [u8; 32])> = idx
            .iter()
            .map(|&i| (i, super::super::hash_leaf_ext(vals[i])))
            .collect();

        assert!(expand(depth, &leaves, &stream[..stream.len() - 1]).is_none());
        let mut long = stream.clone();
        long.push([0u8; 32]);
        assert!(expand(depth, &leaves, &long).is_none());

        // An altered sibling still expands, to paths that no longer reach the root.
        let mut bad = stream.clone();
        bad[3][0] ^= 1;
        let (root, back) = expand(depth, &leaves, &bad).unwrap();
        assert_ne!(root, t.root());
        assert!(idx
            .iter()
            .zip(&back)
            .any(|(&i, p)| !verify_path_ext(&t.root(), i, vals[i], p)));
    }

    #[test]
    fn two_leaves_at_one_index_must_agree() {
        let depth = 4;
        let (t, vals) = tree(depth);
        let p = t.open(9);
        let stream = compress(depth, &[(9, p.as_slice())]).unwrap();
        let a = super::super::hash_leaf_ext(vals[9]);
        let b = super::super::hash_leaf_ext(vals[8]);
        assert!(expand(depth, &[(9, a), (9, b)], &stream).is_none());
        assert!(expand(depth, &[(9, a), (9, a)], &stream).is_some());
    }

    #[test]
    fn an_index_outside_the_tree_is_refused() {
        assert!(expand(4, &[(16, [0u8; 32])], &[[0u8; 32]; 4]).is_none());
        assert!(compress(4, &[(16, &[[0u8; 32]; 4][..])]).is_none());
    }
}
