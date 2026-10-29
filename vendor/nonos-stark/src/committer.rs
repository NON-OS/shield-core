// NONOS Operating System (AGPL-3.0-or-later)

//! A wide trace commitment the host may supply, such as a browser's GPU. The
//! committer gets the columns' coefficients, every coset's shift and the coset
//! root's powers, and returns the tree from the kept level up. Before any of it
//! is used, chunks of leaves are recomputed here from the coefficients, by
//! evaluating each column at the chunk's points, and must open against the
//! returned tree, and parents are sampled on every level above. A tree that
//! passes and is still wrong somewhere makes a proof that fails its own
//! verification, which the prover answers by proving again without it.

use crate::field::Fp;
use crate::merkle::{hash_leaf_wide, TreeTop};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

/// What a committer is handed.
pub struct WideCommit<'a> {
    pub coeffs: &'a [Vec<Fp>],
    pub shifts: &'a [Fp],
    pub twiddles: &'a [Fp],
    pub t: usize,
    pub blowup: usize,
    pub cut: usize,
}

/// The tree's levels from `cut` up, or `None` to commit here instead.
pub type Committer = fn(&WideCommit<'_>) -> Option<Vec<Vec<[u8; 32]>>>;

static COMMITTER: AtomicUsize = AtomicUsize::new(0);

/// Use `c` for every wide trace commitment from now on.
pub fn set_committer(c: Committer) {
    COMMITTER.store(c as usize, Ordering::SeqCst);
}

/// Commit here again.
pub fn clear_committer() {
    COMMITTER.store(0, Ordering::SeqCst);
}

/// Whether a committer is in use.
pub fn active() -> bool {
    COMMITTER.load(Ordering::SeqCst) != 0
}

/// Chunks of leaves recomputed here before a supplied tree is used.
const CHUNKS_CHECKED: usize = 8;

/// The supplied tree for `job`, when there is a committer and its tree passes the checks.
pub(crate) fn supplied(job: &WideCommit<'_>) -> Option<TreeTop> {
    let raw = COMMITTER.load(Ordering::SeqCst);
    if raw == 0 {
        return None;
    }
    // SAFETY: only `set_committer` stores a non-zero value, and it stores a `Committer`.
    let c: Committer = unsafe { core::mem::transmute::<usize, Committer>(raw) };
    let top = TreeTop::from_layers_checked(job.cut, c(job)?)?;
    let n = job.t * job.blowup;
    if top.leaves() != n {
        return None;
    }
    // Chunks spread over the tree from its own root, so the committer cannot know them first.
    let root = top.root();
    let chunk = top.chunk();
    let mut pick = u64::from_le_bytes(root[..8].try_into().ok()?);
    for _ in 0..CHUNKS_CHECKED {
        pick = pick.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        let first = ((pick >> 11) as usize % (n / chunk)) * chunk;
        let leaves: Vec<[u8; 32]> = (first..first + chunk).map(|p| leaf(job, p)).collect();
        if top.open(first, &leaves).is_empty() {
            return None;
        }
    }
    Some(top)
}

/// Leaf `p`: row `p / blowup` of coset `p % blowup`, every column evaluated there directly.
fn leaf(job: &WideCommit<'_>, p: usize) -> [u8; 32] {
    let (c, i) = (p % job.blowup, p / job.blowup);
    let sub = job.twiddles.get(1).copied().unwrap_or(Fp::ONE);
    let x = job.shifts[c] * sub.pow(i as u64);
    let row: Vec<Fp> = job
        .coeffs
        .iter()
        .map(|cf| cf.iter().rev().fold(Fp::ZERO, |acc, &a| acc * x + a))
        .collect();
    hash_leaf_wide(&row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fri::root_of_unity;
    use crate::merkle::MerkleTree;
    use crate::poly::lde_from_coeffs;
    extern crate std;

    fn tree(job: &WideCommit<'_>) -> MerkleTree {
        let n = job.t * job.blowup;
        let mut digests = alloc::vec![[0u8; 32]; n];
        for c in 0..job.blowup {
            let cols: Vec<Vec<Fp>> = job
                .coeffs
                .iter()
                .map(|cf| lde_from_coeffs(cf, job.shifts[c], job.twiddles[1], job.t))
                .collect();
            for i in 0..job.t {
                let row: Vec<Fp> = cols.iter().map(|col| col[i]).collect();
                digests[c + job.blowup * i] = hash_leaf_wide(&row);
            }
        }
        MerkleTree::from_leaf_digests(digests, hash_leaf_wide(&alloc::vec![Fp::ZERO; job.coeffs.len()]))
    }

    fn honest(job: &WideCommit<'_>) -> Option<Vec<Vec<[u8; 32]>>> {
        Some(tree(job).layers()[job.cut..].to_vec())
    }

    fn one_leaf_node_wrong(job: &WideCommit<'_>) -> Option<Vec<Vec<[u8; 32]>>> {
        let mut layers = honest(job)?;
        // Every kept node wrong in one byte: any chunk checked must catch it.
        for d in layers[0].iter_mut() {
            d[0] ^= 1;
        }
        Some(layers)
    }

    fn upper_level_wrong(job: &WideCommit<'_>) -> Option<Vec<Vec<[u8; 32]>>> {
        let mut layers = honest(job)?;
        layers[1][0][5] ^= 0x40;
        Some(layers)
    }

    #[test]
    fn a_supplied_tree_is_used_only_when_it_is_the_one_computed_here() {
        let log_t = 4;
        let t = 1usize << log_t;
        let blowup = 16;
        let sub = root_of_unity(log_t);
        let coeffs: Vec<Vec<Fp>> = (0..3)
            .map(|j| (0..40).map(|i| Fp::from_u64(1 + 7 * i as u64 + 1000 * j as u64)).collect())
            .collect();
        let shifts: Vec<Fp> = (0..blowup).map(|c| Fp::from_u64(3 + c as u64 * 11)).collect();
        let twiddles: Vec<Fp> = (0..t / 2).map(|k| sub.pow(k as u64)).collect();
        let job = WideCommit { coeffs: &coeffs, shifts: &shifts, twiddles: &twiddles, t, blowup, cut: 3 };
        let want = tree(&job).root();

        set_committer(honest);
        assert_eq!(supplied(&job).map(|top| top.root()), Some(want));
        set_committer(one_leaf_node_wrong);
        assert!(supplied(&job).is_none());
        set_committer(upper_level_wrong);
        assert!(supplied(&job).is_none());
        clear_committer();
        assert!(supplied(&job).is_none());
    }
}
