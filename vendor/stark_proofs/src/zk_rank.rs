// NONOS Operating System (AGPL-3.0-or-later)
//! Condition (R) of docs/12-zero-knowledge.md Section 4.4, decided for one launch
//! proof fast enough to run on a phone before the proof is sent.
//!
//! (R) asks that the mask columns, over the kernel of their own openings,
//! span everything FRI reveals beyond layer zero. Two facts make it cheap.
//!
//! The mask is a base-field polynomial and is opened at `z` and `g z` in
//! F_p^2, so vanishing there means vanishing at their conjugates too: the
//! masks that pass their `z` openings are exactly `q(x) x^s`, with
//! `q = (x - z)(x - z')(x - g z)(x - g z')` of degree four and base-field
//! coefficients. For such a mask the DEEP part is `x^s R_c(x)`, one fixed
//! cubic per mask column, so every FRI fold of it has at most two terms and
//! every revealed value costs a few multiplications.
//!
//! A random subset `W` of that basis then certifies (R) one way only: the rank
//! of [row openings; FRI beyond layer zero] over `W` is at most 304 + the
//! rank of FRI over the kernel, which is at most what the simulator's
//! uniform DEEP polynomial reveals, which is at most `U`, a count of free
//! values from the positions alone. So a rank of `304 + U` over `W` proves
//! (R). A shortfall proves nothing and another subset is drawn.

use crate::crypto::stark::air::replay_pre::replay_comp_z_pre;
use crate::crypto::stark::air::{
    domain_params_blown, Air, StarkProofExtRounds, WiredMultiGen, COSET_SHIFT,
};
use crate::crypto::stark::field::{Fp, Fp2, P};
use crate::crypto::stark::fri::{root_of_unity, FOLD, FRI_FOLD_LOG};
use crate::crypto::stark::fri_ext::{fri_fold_challenges_ext, fri_positions_ext};
use crate::crypto::stark::par;
use crate::proof_wire::{deserialize_rounds, ParamSet};
use crate::shield::join::join_split_shape;
use crate::shield::member::TREE_DEPTH;
use crate::shield_params::direct;
use alloc::vec::Vec;

/// Values a fold reads: the leaf a query opens at every layer.
const RADIX: usize = FOLD;
/// Halvings a layer takes.
const LOG_RADIX: usize = FRI_FOLD_LOG as usize;
/// The fewest FRI layers a certified proof may have: the shape the certificate
/// was checked on. The launch folds four times at radix 4, the `fri8` build three at radix 8.
const MIN_LAYERS: usize = 3;

/// What the check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RankReport {
    /// The free values FRI reveals beyond layer zero, from the positions.
    pub bound: usize,
    /// The rank the mask reached over the sampled basis, less the row
    /// openings, 152 rows of two columns. (R) holds when this equals `bound`.
    pub mask_rank: usize,
    pub attempts: usize,
    pub holds: bool,
}

fn conj(v: Fp2) -> Fp2 {
    Fp2::new(v.c0, Fp::ZERO - v.c1)
}

/// Polynomial product over F_p^2, coefficients low first.
fn mul(a: &[Fp2], b: &[Fp2]) -> Vec<Fp2> {
    let mut out = alloc::vec![Fp2::ZERO; a.len() + b.len() - 1];
    for (i, x) in a.iter().enumerate() {
        for (j, y) in b.iter().enumerate() {
            out[i + j] = out[i + j] + *x * *y;
        }
    }
    out
}

/// `p / (x - r)` for `p` vanishing at `r`: synthetic division.
fn div_linear(p: &[Fp2], r: Fp2) -> Vec<Fp2> {
    let mut q = alloc::vec![Fp2::ZERO; p.len() - 1];
    let mut acc = Fp2::ZERO;
    for i in (1..p.len()).rev() {
        acc = acc * r + p[i];
        q[i - 1] = acc;
    }
    q
}

struct Xorshift(u64);
impl Xorshift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Incremental row echelon over F_p: add rows until the rank reaches
/// `target` or the rows run out. The one-row-at-a-time form, kept as the
/// reference `Batched` is held to.
#[cfg(test)]
struct Echelon {
    rows: Vec<(usize, Vec<Fp>)>,
}

#[cfg(test)]
impl Echelon {
    fn add(&mut self, mut v: Vec<Fp>) {
        for (p, b) in &self.rows {
            let f = v[*p];
            if f != Fp::ZERO {
                for (x, y) in v.iter_mut().zip(b).skip(*p) {
                    *x = *x - f * *y;
                }
            }
        }
        if let Some(p) = v.iter().position(|x| *x != Fp::ZERO) {
            let inv = v[p].inv();
            for x in v.iter_mut().skip(p) {
                *x = *x * inv;
            }
            self.rows.push((p, v));
        }
    }
}

/// Reduce `v` against rows kept in echelon form: each has zeros before its
/// pivot and at every earlier row's pivot.
fn reduce(v: &mut [Fp], rows: &[(usize, Vec<Fp>)]) {
    for (p, b) in rows {
        let f = v[*p];
        if f != Fp::ZERO {
            for (x, y) in v.iter_mut().zip(b).skip(*p) {
                *x = *x - f * *y;
            }
        }
    }
}

/// The same echelon reached in batches, in parallel, with the same rank at
/// every prefix of the rows. A batch's rows are reduced against the rows
/// already kept, each on its own; then each new pivot clears the batch rows
/// below it, again each on its own. Exact arithmetic, so the pivots and the
/// rank do not depend on the thread count. It was a single core's 16 to 20
/// seconds, a fifth of a launch proof.
struct Batched {
    rows: Vec<(usize, Vec<Fp>)>,
}

impl Batched {
    fn extend(&mut self, mut batch: Vec<Vec<Fp>>, target: usize) {
        let kept = &self.rows;
        par::for_each_chunk_mut(&mut batch, 1, |chunk| {
            for v in chunk.iter_mut() {
                reduce(v, kept);
            }
        });
        for i in 0..batch.len() {
            if self.rows.len() >= target {
                return;
            }
            let Some(p) = batch[i].iter().position(|x| *x != Fp::ZERO) else {
                continue;
            };
            let inv = batch[i][p].inv();
            for x in batch[i].iter_mut().skip(p) {
                *x = *x * inv;
            }
            let pivot = core::mem::take(&mut batch[i]);
            par::for_each_chunk_mut(&mut batch[i + 1..], 8, |chunk| {
                for v in chunk.iter_mut() {
                    let f = v[p];
                    if f != Fp::ZERO {
                        for (x, y) in v.iter_mut().zip(&pivot).skip(p) {
                            *x = *x - f * *y;
                        }
                    }
                }
            });
            self.rows.push((p, pivot));
        }
    }
}

/// Decide (R) for a launch proof and its 36 public words. `attempts` bounds
/// the subsets drawn; each is independent, so one shortfall is not a verdict.
pub fn check_fri_rank(
    proof: &[u8],
    publics: &[u64],
    attempts: usize,
) -> Result<RankReport, alloc::string::String> {
    check_at(proof, publics, attempts, None)
}

/// `check_fri_rank` at chosen query positions instead of the proof's own: the
/// rank depends on the positions, the challenges and the coefficients, and on
/// none of the opened values, so a test can place the queries where it likes.
pub(crate) fn check_at(
    proof: &[u8],
    publics: &[u64],
    attempts: usize,
    chosen: Option<Vec<usize>>,
) -> Result<RankReport, alloc::string::String> {
    check_at_shape(
        proof,
        publics,
        attempts,
        chosen,
        direct::N_QUERIES,
        direct::GRIND_BITS,
    )
}

/// `check_fri_rank` at another query shape: `q` queries and `grind` bits.
pub fn check_fri_rank_shape(
    proof: &[u8],
    publics: &[u64],
    attempts: usize,
    q: usize,
    grind: u32,
) -> Result<RankReport, alloc::string::String> {
    check_at_shape(proof, publics, attempts, None, q, grind)
}

fn check_at_shape(
    proof: &[u8],
    publics: &[u64],
    attempts: usize,
    chosen: Option<Vec<usize>>,
    q: usize,
    grind: u32,
) -> Result<RankReport, alloc::string::String> {
    if publics.iter().any(|&v| v >= P) {
        return Err("a public word is not below p".into());
    }
    let extra = direct::EXTRA_BLOWUP_BITS;
    let words: Vec<Fp> = publics.iter().map(|&v| Fp::from_u64(v)).collect();
    let mut air = join_split_shape(TREE_DEPTH, &words);
    let params = ParamSet::of(&air, q, grind, extra);
    let rounds = deserialize_rounds(proof, &params)
        .ok_or("not a proof at the launch point for this circuit")?;
    rank_of(&mut air, &rounds, &words, extra, attempts, chosen)
}

/// Decide (R) for any wired circuit's two-round proof, from the circuit's
/// shape, its public words and the extra blowup it was proven at. The rank
/// depends on the shape, the positions, the challenges and the coefficients,
/// so a statement other than the join-split is certified the same way, by the
/// same code: `check_fri_rank` is this over the launch shape.
pub fn check_fri_rank_rounds(
    mut air: WiredMultiGen,
    rounds: &StarkProofExtRounds,
    publics: &[Fp],
    extra: u32,
    attempts: usize,
) -> Result<RankReport, alloc::string::String> {
    rank_of(&mut air, rounds, publics, extra, attempts, None)
}

fn rank_of(
    air: &mut WiredMultiGen,
    rounds: &StarkProofExtRounds,
    words: &[Fp],
    extra: u32,
    attempts: usize,
    chosen: Option<Vec<usize>>,
) -> Result<RankReport, alloc::string::String> {
    let replayed = replay_comp_z_pre(air, &rounds.pre, Some(&rounds.perm_root), extra, words)?;

    let (log_n, fri_log_blowup) = domain_params_blown(&*air, extra);
    let n = 1usize << log_n;
    let bound_deg = n >> fri_log_blowup;
    let fri = &rounds.pre.proof.fri;
    let layers = fri.roots.len();
    /*
     * The certificate was built and checked on proofs that fold at least three
     * times. A circuit small enough to fold once falls short by one pair of
     * functionals per query, whatever the seed, and that case has not been
     * analysed. Refuse it rather than certify or fail it for a reason nobody
     * has written down. Pad such a circuit to the pool's length instead.
     */
    if layers < MIN_LAYERS {
        return Err(alloc::format!(
            "the proof folds {layers} times; the certificate covers {MIN_LAYERS} or more, so pad the circuit"
        ));
    }
    let final_len = bound_deg >> (LOG_RADIX * layers);
    let betas = fri_fold_challenges_ext(fri, Some(&replayed.seed));
    let positions = match chosen {
        Some(p) => p,
        None => fri_positions_ext(fri, log_n, Some(&replayed.seed)),
    };
    let width = air.trace_width();
    let window = air.window_size();
    let mask = [width - 2, width - 1];
    let t = 1usize << air.log_trace_len();
    let g = root_of_unity(t.trailing_zeros());
    let z = replayed.z;
    let zs = [z, z.mul_base(g)];
    if replayed.deep_coeffs.len() < window * width || window != 2 || betas.len() != layers {
        return Err("the proof's shape is not the launch shape".into());
    }

    // q(x) = (x - z)(x - z')(x - gz)(x - gz'), base-field coefficients.
    let lin = |r: Fp2| alloc::vec![Fp2::ZERO - r, Fp2::ONE];
    let q2 = mul(
        &mul(&lin(zs[0]), &lin(conj(zs[0]))),
        &mul(&lin(zs[1]), &lin(conj(zs[1]))),
    );
    let q_base: Vec<Fp> = q2.iter().map(|v| v.c0).collect();
    // R_c = sum_k a_{k,c} q / (x - z_k): the DEEP part of the mask q x^s is x^s R_c.
    let r_c: Vec<Vec<Fp2>> = mask
        .iter()
        .map(|&c| {
            let mut r = alloc::vec![Fp2::ZERO; 4];
            for (k, &zk) in zs.iter().enumerate() {
                let a = replayed.deep_coeffs[k * width + c];
                for (acc, v) in r.iter_mut().zip(div_linear(&q2, zk)) {
                    *acc = *acc + a * v;
                }
            }
            r
        })
        .collect();

    // The opened points: rows and their successors for the mask openings;
    // per layer the leaf's RADIX points.
    let omega = root_of_unity(log_n);
    let shift = Fp::from_u64(COSET_SHIFT);
    let layer_points: Vec<Vec<Fp>> = (0..layers)
        .map(|m| {
            let size = n >> (LOG_RADIX * m);
            let quarter = size / RADIX;
            let w = omega.pow(1u64 << (LOG_RADIX * m));
            let s = shift.pow(1u64 << (LOG_RADIX * m));
            positions
                .iter()
                .flat_map(|&p| {
                    let i = p % quarter;
                    (0..RADIX).map(move |r| s * w.pow((i + r * quarter) as u64))
                })
                .collect()
        })
        .collect();
    /*
     * Distinct rows only: a query whose leaf is another's successor coset opens
     * the same rows twice, and a repeated opening is one functional, not two.
     */
    let mut row_points: Vec<Fp> = layer_points[0].iter().flat_map(|&x| [x, x * g]).collect();
    row_points.sort_unstable_by_key(|v| v.value());
    row_points.dedup();

    // U: the free values FRI reveals beyond layer zero, from the positions.
    let key = |p: usize, m: usize| p % ((n >> (LOG_RADIX * m)) / RADIX);
    let mut free = 0usize;
    for m in 1..layers {
        let mut children: Vec<usize> = positions.iter().map(|&p| key(p, m)).collect();
        children.sort_unstable();
        children.dedup();
        for &c in &children {
            let mut parents: Vec<usize> = positions
                .iter()
                .filter(|&&p| key(p, m) == c)
                .map(|&p| key(p, m - 1))
                .collect();
            parents.sort_unstable();
            parents.dedup();
            free += RADIX - parents.len();
        }
    }
    let mut last: Vec<usize> = positions.iter().map(|&p| key(p, layers - 1)).collect();
    last.sort_unstable();
    last.dedup();
    free += final_len - last.len();
    let bound = 2 * free;
    /*
     * Each mask column is opened on its own at every row, so the openings are
     * two functionals per row, one per column. Folding them into one row slot
     * would constrain only their sum, a larger kernel than the masks really
     * have, and a certificate over it would pass proofs (R) fails.
     */
    let openings = 2 * row_points.len();
    let target = openings + bound;

    // One row of [row openings; layers 1.. ; final] for the mask q x^s in column `c`.
    let row = |c: usize, s: usize| -> Vec<Fp> {
        let mut out = Vec::with_capacity(target + 64);
        for &y in &row_points {
            let q_y = q_base.iter().rev().fold(Fp::ZERO, |a, v| a * y + *v);
            let v = q_y * y.pow(s as u64);
            out.extend(if c == 0 { [v, Fp::ZERO] } else { [Fp::ZERO, v] });
        }
        let mut terms: Vec<(usize, Fp2)> = (0..4).map(|r| (s + r, r_c[c][r])).collect();
        for m in 0..layers {
            if m > 0 {
                for &y in &layer_points[m] {
                    let v = terms
                        .iter()
                        .fold(Fp2::ZERO, |a, (i, co)| a + co.mul_base(y.pow(*i as u64)));
                    out.push(v.c0);
                    out.push(v.c1);
                }
            }
            let beta = betas[m];
            // beta^r for r < RADIX: a fold over the layer's halvings under beta,
            // beta^2, beta^4, ... maps x^i to beta^(i mod RADIX) y^(i / RADIX).
            let pw: Vec<Fp2> = core::iter::successors(Some(Fp2::ONE), |x| Some(*x * beta))
                .take(RADIX)
                .collect();
            let mut next: Vec<(usize, Fp2)> = Vec::with_capacity(terms.len());
            for (i, co) in terms {
                let (j, v) = (i / RADIX, co * pw[i % RADIX]);
                match next.iter_mut().find(|(k, _)| *k == j) {
                    Some((_, acc)) => *acc = *acc + v,
                    None => next.push((j, v)),
                }
            }
            terms = next;
        }
        let mut fin = alloc::vec![Fp2::ZERO; final_len];
        for (i, co) in terms {
            if i < final_len {
                fin[i] = fin[i] + co;
            }
        }
        for v in fin {
            out.push(v.c0);
            out.push(v.c1);
        }
        out
    };

    let mut rng = Xorshift(
        0x9E37_79B9_7F4A_7C15 ^ u64::from_le_bytes(replayed.seed[..8].try_into().unwrap_or([1; 8])),
    );
    let mut best = 0usize;
    for attempt in 1..=attempts.max(1) {
        /*
         * Up to 3 * target sampled rows, in the order the generator draws them,
         * a batch at a time: enough for the target and a margin, then more only
         * if the rank falls short. The rows are built in parallel too.
         */
        let mut ech = Batched {
            rows: Vec::with_capacity(target),
        };
        let mut tried = 0usize;
        while ech.rows.len() < target && tried < 3 * target {
            let take = (target - ech.rows.len() + 64).min(3 * target - tried);
            let pairs: Vec<(usize, usize)> = (0..take)
                .map(|_| {
                    let c = (rng.next() % 2) as usize;
                    let s = (rng.next() as usize) % (bound_deg - 4);
                    (c, s)
                })
                .collect();
            let batch = par::map_index(take, |k| row(pairs[k].0, pairs[k].1));
            ech.extend(batch, target);
            tried += take;
        }
        let reached = ech.rows.len().saturating_sub(openings);
        best = best.max(reached);
        if ech.rows.len() >= target {
            return Ok(RankReport {
                bound,
                mask_rank: bound,
                attempts: attempt,
                holds: true,
            });
        }
    }
    Ok(RankReport {
        bound,
        mask_rank: best,
        attempts: attempts.max(1),
        holds: false,
    })
}

