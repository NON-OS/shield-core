// NONOS Operating System (AGPL-3.0-or-later)

//! A wide trace commitment the host may supply, such as a browser's GPU. The
//! committer gets the columns' coefficients, every coset's shift and the coset
//! root's powers, and returns the tree from the kept level up. Before any of it
//! is used, chunks of leaves are recomputed here from the coefficients, by
//! evaluating each column at the chunk's points, and must open against the
//! returned tree, and parents are sampled on every level above. A tree that
//! passes and is still wrong somewhere makes a proof that fails its own
//! verification, which the prover answers by proving again without it.

use crate::field::{Fp, Fp2};
use crate::merkle::{hash_leaf_ext, hash_leaf_wide, MerkleTree, TreeTop};
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

/// Commit here again, every tree, and take the DEEP pass back.
pub fn clear_committer() {
    COMMITTER.store(0, Ordering::SeqCst);
    EXT_COMMITTER.store(0, Ordering::SeqCst);
    DEEP.store(0, Ordering::SeqCst);
}

/// What a DEEP evaluator is handed: the 2 (window + 1) combined polynomials, the domain, the
/// composition's values, and the constants of every quotient.
pub struct DeepJob<'a> {
    pub combined: &'a [Vec<Fp>],
    pub shifts: &'a [Fp],
    pub sub: Fp,
    pub t: usize,
    pub blowup: usize,
    pub comp: &'a [Fp2],
    pub zks: &'a [Fp2],
    pub z: Fp2,
    pub claims: &'a [Fp2],
    pub e: Fp2,
    pub comp_z: Fp2,
    pub periodic_claim: Fp2,
}

/// The DEEP values over the domain, or `None` to compute them here.
pub type DeepEvaluator = fn(&DeepJob<'_>) -> Option<Vec<Fp2>>;

static DEEP: AtomicUsize = AtomicUsize::new(0);

/// Use `d` for every DEEP pass from now on.
pub fn set_deep(d: DeepEvaluator) {
    DEEP.store(d as usize, Ordering::SeqCst);
}

/// Whether a DEEP evaluator is in use.
pub fn deep_active() -> bool {
    DEEP.load(Ordering::SeqCst) != 0
}

/// Points of a supplied DEEP pass recomputed here before it is used.
const POINTS_CHECKED: usize = 32;

/// The supplied DEEP values for `job`, when there is an evaluator and its values agree with the
/// formula at points picked from them.
pub fn deep_values(job: &DeepJob<'_>) -> Option<Vec<Fp2>> {
    let raw = DEEP.load(Ordering::SeqCst);
    if raw == 0 {
        return None;
    }
    // SAFETY: only `set_deep` stores a non-zero value, and it stores a `DeepEvaluator`.
    let d: DeepEvaluator = unsafe { core::mem::transmute::<usize, DeepEvaluator>(raw) };
    let n = job.t * job.blowup;
    let values = d(job).filter(|v| v.len() == n)?;
    let mut pick = values.iter().fold(0x9e37_79b9_7f4a_7c15u64, |h, v| {
        h.rotate_left(5) ^ v.c0.value() ^ v.c1.value().rotate_left(17)
    });
    for _ in 0..POINTS_CHECKED {
        pick = pick.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        let j = (pick >> 11) as usize % n;
        if values[j] != deep_at(job, j) {
            return None;
        }
    }
    Some(values)
}

/// The DEEP value at position `j`, every combined polynomial evaluated there directly.
fn deep_at(job: &DeepJob<'_>, j: usize) -> Fp2 {
    let (c, i) = (j % job.blowup, j / job.blowup);
    let xb = job.shifts[c] * job.sub.pow(i as u64);
    let x = Fp2::from_base(xb);
    let at = |k: usize| job.combined[k].iter().rev().fold(Fp::ZERO, |acc, &a| acc * xb + a);
    let window = job.zks.len();
    let mut acc = Fp2::ZERO;
    for k in 0..window {
        let v = Fp2::new(at(2 * k), at(2 * k + 1));
        acc = acc + (v - job.claims[k]) * (x - job.zks[k]).inv();
    }
    let inv_z = (x - job.z).inv();
    acc = acc + job.e * ((job.comp[j] - job.comp_z) * inv_z);
    let pv = Fp2::new(at(2 * window), at(2 * window + 1));
    acc + (pv - job.periodic_claim) * inv_z
}

/// Whether a committer is in use.
pub fn active() -> bool {
    COMMITTER.load(Ordering::SeqCst) != 0 || EXT_COMMITTER.load(Ordering::SeqCst) != 0
}

/// The composition tree of extension values from `cut` up, or `None` to build it here.
pub type ExtCommitter = fn(&[Fp2], usize) -> Option<Vec<Vec<[u8; 32]>>>;

static EXT_COMMITTER: AtomicUsize = AtomicUsize::new(0);

/// Use `c` for every composition tree from now on.
pub fn set_ext_committer(c: ExtCommitter) {
    EXT_COMMITTER.store(c as usize, Ordering::SeqCst);
}

/// The composition tree of `values` from `cut` up: supplied, when there is a committer and its
/// tree opens at checked chunks of leaves hashed here, else built here.
pub fn ext_top(values: &[Fp2], cut: usize) -> Option<TreeTop> {
    let raw = EXT_COMMITTER.load(Ordering::SeqCst);
    if raw != 0 && values.len().is_power_of_two() {
        // SAFETY: only `set_ext_committer` stores a non-zero value, and it stores an `ExtCommitter`.
        let c: ExtCommitter = unsafe { core::mem::transmute::<usize, ExtCommitter>(raw) };
        if let Some(top) = c(values, cut).and_then(|l| TreeTop::from_layers_checked(cut, l)) {
            if top.leaves() == values.len() && ext_checks(&top, values) {
                return Some(top);
            }
        }
    }
    TreeTop::of(&MerkleTree::commit_ext(values), cut)
}

fn ext_checks(top: &TreeTop, values: &[Fp2]) -> bool {
    let chunk = top.chunk();
    let mut pick = u64::from_le_bytes(top.root()[..8].try_into().unwrap_or([0; 8]));
    (0..CHUNKS_CHECKED).all(|_| {
        pick = pick.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        let first = ((pick >> 11) as usize % (values.len() / chunk)) * chunk;
        let leaves: Vec<[u8; 32]> = values[first..first + chunk].iter().map(|v| hash_leaf_ext(*v)).collect();
        !top.open(first, &leaves).is_empty()
    })
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

#[cfg(test)]
mod ext_tests {
    use super::*;

    fn honest(values: &[Fp2], cut: usize) -> Option<Vec<Vec<[u8; 32]>>> {
        Some(MerkleTree::commit_ext(values).layers()[cut..].to_vec())
    }

    fn wrong(values: &[Fp2], cut: usize) -> Option<Vec<Vec<[u8; 32]>>> {
        let mut l = honest(values, cut)?;
        for d in l[0].iter_mut() {
            d[3] ^= 2;
        }
        Some(l)
    }

    #[test]
    fn a_supplied_composition_tree_is_used_only_when_it_is_right() {
        let values: Vec<Fp2> =
            (0..1024u64).map(|i| Fp2::new(Fp::from_u64(i * 31 + 5), Fp::from_u64(i ^ 77))).collect();
        let want = MerkleTree::commit_ext(&values).root();
        set_ext_committer(honest);
        assert_eq!(ext_top(&values, 6).map(|t| t.root()), Some(want));
        set_ext_committer(wrong);
        // Refused, and built here instead: the right root either way.
        assert_eq!(ext_top(&values, 6).map(|t| t.root()), Some(want));
        clear_committer();
    }
}

#[cfg(test)]
mod deep_tests {
    use super::*;
    use crate::fri::root_of_unity;

    fn right(job: &DeepJob<'_>) -> Option<Vec<Fp2>> {
        Some((0..job.t * job.blowup).map(|j| deep_at(job, j)).collect())
    }

    fn off(job: &DeepJob<'_>) -> Option<Vec<Fp2>> {
        let mut v = right(job)?;
        for (j, x) in v.iter_mut().enumerate() {
            if j % 4 == 1 {
                *x = *x + Fp2::ONE;
            }
        }
        Some(v)
    }

    #[test]
    fn supplied_deep_values_are_used_only_when_they_agree_with_the_formula() {
        let (t, blowup) = (16usize, 8usize);
        let f = |a: u64| Fp::from_u64(a);
        let e2 = |a: u64| Fp2::new(f(a), f(a * 3 + 1));
        let combined: Vec<Vec<Fp>> = (0..6).map(|k| (0..20).map(|i| f(i * 7 + k * 100 + 1)).collect()).collect();
        let shifts: Vec<Fp> = (0..blowup).map(|c| f(3 + c as u64)).collect();
        let comp: Vec<Fp2> = (0..t * blowup).map(|j| e2(j as u64 + 9)).collect();
        let zks = [e2(11), e2(12)];
        let claims = [e2(13), e2(14)];
        let job = DeepJob {
            combined: &combined,
            shifts: &shifts,
            sub: root_of_unity(4),
            t,
            blowup,
            comp: &comp,
            zks: &zks,
            z: e2(15),
            claims: &claims,
            e: e2(16),
            comp_z: e2(17),
            periodic_claim: e2(18),
        };
        set_deep(right);
        assert!(deep_values(&job).is_some());
        set_deep(off);
        assert!(deep_values(&job).is_none());
        clear_committer();
        assert!(deep_values(&job).is_none());
    }
}
