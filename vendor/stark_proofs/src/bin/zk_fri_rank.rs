// NONOS Operating System (AGPL-3.0-or-later)
//! The rank condition behind zero-knowledge for FRI beyond layer zero,
//! checked on a real launch proof.
//!
//!     zk_fri_rank <transcript-kat.json> <report.json> [threads=<n>] [mask_log=<k>]
//!
//! `mask_log` sizes the mask polynomials at `2^k` coefficients instead of the
//! prover's `2^17`. A mask that small must fail: it is the control that shows
//! the check can.
//!
//! FRI reveals, beyond the layer-zero values the trace openings already fix,
//! the opened values of layers one to three and the final layer's
//! coefficients: linear functionals `F` of the DEEP polynomial. A simulator
//! that knows only the public words samples the DEEP polynomial uniformly
//! among those of degree below `B - 1` that agree with the layer-zero values
//! it already chose; what it reveals is then uniform on the image of `F` over
//! `ker(layer 0)`.
//!
//! The real DEEP polynomial is the witness part plus the mask part
//! `D_M = sum_k a_k (N(x) - N(z_k)) / (x - z_k)` for the pair `N = M_a + X M_b`,
//! with `M_c` uniform of degree below `B` and constrained only by what the
//! proof opens of it: each column at the queried rows and their successors,
//! and `N` at `z` and `g z`. The two distributions agree exactly when the mask, over the kernel
//! of its own openings `A`, spans the same space the simulator's does:
//!
//!     rank(F on ker A, over the mask)  ==  rank(F on ker layer0, over any D)
//!
//! Both sides are measured here over F_p from random samples, with this
//! proof's own challenges read from its transcript vector: `z`, the DEEP
//! alpha, the fold challenges and the query positions. Equality is the rank
//! lemma for this instance. The inclusion one way is automatic (the mask part
//! vanishes at layer zero on `ker A`), so equality is the whole question.

use stark_proofs::crypto::stark::field::{Fp, Fp2};
use stark_proofs::crypto::stark::fri::root_of_unity;
use stark_proofs::host::{die, read_text};

const LOG_N: u32 = 23;
const LOG_B: u32 = 17;
const LOG_T: u32 = 13;
const WIDTH: usize = 44;
const MASK: [usize; 2] = [42, 43];
const LAYERS: usize = 4;
const RADIX: usize = 4;

struct Instance {
    z: Fp2,
    alpha: Fp2,
    betas: Vec<Fp2>,
    positions: Vec<usize>,
}

/// The draws of a launch transcript vector, in the order the verifier makes
/// them: beta, gamma, the composition alpha, z, the DEEP alpha, one fold
/// challenge per layer, then the query indices.
fn instance(path: &str) -> Instance {
    let text = read_text(path);
    let mut fp2 = Vec::new();
    let mut half: Option<u64> = None;
    let mut idx = Vec::new();
    for line in text.lines() {
        let op = |name: &str| line.contains(&format!("\"op\": \"{name}\""));
        let word = || -> u64 {
            let at = line.find("\"word\": \"").unwrap_or_else(|| die("a draw without its word")) + 9;
            u64::from_str_radix(&line[at..at + 16], 16).unwrap_or_else(|_| die("a word that is not hex"))
        };
        if op("challenge_fp2_c0") {
            half = Some(word());
        } else if op("challenge_fp2_c1") {
            let c0 = half.take().unwrap_or_else(|| die("an extension draw without its first half"));
            fp2.push(Fp2::new(Fp::from_u64(c0), Fp::from_u64(word())));
        } else if op("challenge_index") {
            idx.push((word() as usize) & ((1usize << LOG_N) - 1));
        }
    }
    if fp2.len() != 5 + LAYERS || idx.is_empty() {
        die(&format!("expected {} extension draws and the query indices, found {} and {}", 5 + LAYERS, fp2.len(), idx.len()));
    }
    Instance { z: fp2[3], alpha: fp2[4], betas: fp2[5..].to_vec(), positions: idx }
}

/// A small generator: the samples need independence, not secrecy.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn fp(&mut self) -> Fp {
        Fp::from_u64(self.next())
    }
}

fn eval_base_at_base(c: &[Fp], x: Fp) -> Fp {
    c.iter().rev().fold(Fp::ZERO, |a, &v| a * x + v)
}

fn eval_base_at_ext(c: &[Fp], x: Fp2) -> Fp2 {
    c.iter().rev().fold(Fp2::ZERO, |a, &v| a * x + Fp2::from_base(v))
}

fn eval_ext_at_base(c: &[Fp2], x: Fp) -> Fp2 {
    c.iter().rev().fold(Fp2::ZERO, |a, &v| a.mul_base(x) + v)
}

/// `(M(x) - M(z)) / (x - z)` by synthetic division: one coefficient fewer.
fn quotient(m: &[Fp], z: Fp2) -> Vec<Fp2> {
    let n = m.len();
    let mut q = vec![Fp2::ZERO; n - 1];
    let mut acc = Fp2::ZERO;
    for i in (1..n).rev() {
        acc = acc * z + Fp2::from_base(m[i]);
        q[i - 1] = acc;
    }
    q
}

/// One radix-four fold in coefficients: `c'_j = sum_r beta^r c_{4j+r}`, the
/// two radix-two folds under beta and beta squared the prover applies.
fn fold(c: &[Fp2], beta: Fp2) -> Vec<Fp2> {
    let pw = [Fp2::ONE, beta, beta * beta, beta * beta * beta];
    c.chunks(RADIX).map(|q| q.iter().zip(pw).fold(Fp2::ZERO, |a, (v, p)| a + *v * p)).collect()
}

struct Geometry {
    /// Per layer, the opened points: `RADIX` per query.
    layer_points: Vec<Vec<Fp>>,
    /// The mask's opened rows: the layer-zero points and their successors.
    mask_points: Vec<Fp>,
    g: Fp,
}

fn geometry(inst: &Instance) -> Geometry {
    let n = 1usize << LOG_N;
    let omega = root_of_unity(LOG_N);
    let g = root_of_unity(LOG_T);
    let shift = Fp::from_u64(7);
    let mut layer_points = Vec::new();
    for m in 0..LAYERS {
        let size = n >> (2 * m);
        let quarter = size / RADIX;
        let w = omega.pow(1u64 << (2 * m));
        let s = shift.pow(1u64 << (2 * m));
        let pts: Vec<Fp> = inst
            .positions
            .iter()
            .flat_map(|&q| {
                let i = q % quarter;
                (0..RADIX).map(move |r| s * w.pow((i + r * quarter) as u64))
            })
            .collect();
        layer_points.push(pts);
    }
    let mask_points = layer_points[0].iter().flat_map(|&x| [x, x * g]).collect();
    Geometry { layer_points, mask_points, g }
}

/// Everything FRI reveals of `d`, as base-field coordinates: layer-zero
/// values, the opened values of layers one to three, the final coefficients.
fn fri_row(d: &[Fp2], inst: &Instance, geo: &Geometry, out: &mut Vec<Fp>) {
    let mut cur = d.to_vec();
    for m in 0..LAYERS {
        for &x in &geo.layer_points[m] {
            let v = eval_ext_at_base(&cur, x);
            out.push(v.c0);
            out.push(v.c1);
        }
        cur = fold(&cur, inst.betas[m]);
    }
    for v in &cur {
        out.push(v.c0);
        out.push(v.c1);
    }
}

fn layer0_width(geo: &Geometry) -> usize {
    2 * geo.layer_points[0].len()
}

/// A mask sample: its openings `A`, then what FRI reveals of its DEEP part.
fn mask_row(seed: u64, inst: &Instance, geo: &Geometry, mask_log: u32) -> Vec<Fp> {
    let b = 1usize << LOG_B;
    let mb = 1usize << mask_log;
    let mut rng = Rng(seed | 1);
    let zs = [inst.z, inst.z.mul_base(geo.g)];
    let mut row = Vec::new();
    let mut d = vec![Fp2::ZERO; b - 1];
    // The pair is opened at z_k as one F_p^2 value, N = M_a + X M_b, and DEEP
    // gives column b the coefficient X times column a's.
    let x = Fp2::new(Fp::ZERO, Fp::ONE);
    let mut at_z = [Fp2::ZERO; 2];
    for j in 0..MASK.len() {
        let m: Vec<Fp> = (0..mb).map(|_| rng.fp()).collect();
        for &p in &geo.mask_points {
            row.push(eval_base_at_base(&m, p));
        }
        for (k, &zk) in zs.iter().enumerate() {
            let v = eval_base_at_ext(&m, zk);
            at_z[k] = at_z[k] + if j == 0 { v } else { x * v };
        }
        for (k, &zk) in zs.iter().enumerate() {
            let a0 = inst.alpha.pow((k * WIDTH + MASK[0]) as u64);
            let a = if j == 0 { a0 } else { a0 * x };
            for (acc, q) in d.iter_mut().zip(quotient(&m, zk)) {
                *acc = *acc + a * q;
            }
        }
    }
    for v in at_z {
        row.push(v.c0);
        row.push(v.c1);
    }
    fri_row(&d, inst, geo, &mut row);
    row
}

/// A simulator sample: any DEEP polynomial of degree below `B - 1`.
fn any_row(seed: u64, inst: &Instance, geo: &Geometry) -> Vec<Fp> {
    let b = 1usize << LOG_B;
    let mut rng = Rng(seed | 1);
    let d: Vec<Fp2> = (0..b - 1).map(|_| Fp2::new(rng.fp(), rng.fp())).collect();
    let mut row = Vec::new();
    fri_row(&d, inst, geo, &mut row);
    row
}

/// The rank over F_p of `rows` restricted to columns `cols`.
fn rank(rows: &[Vec<Fp>], cols: core::ops::Range<usize>) -> usize {
    let mut basis: Vec<(usize, Vec<Fp>)> = Vec::new();
    for r in rows {
        let mut v: Vec<Fp> = r[cols.clone()].to_vec();
        for (p, b) in &basis {
            let f = v[*p];
            if f != Fp::ZERO {
                for (x, y) in v.iter_mut().zip(b) {
                    *x = *x - f * *y;
                }
            }
        }
        if let Some(p) = v.iter().position(|x| *x != Fp::ZERO) {
            let inv = v[p].inv();
            for x in v.iter_mut() {
                *x = *x * inv;
            }
            basis.push((p, v));
        }
    }
    basis.len()
}

fn sample(k: usize, threads: usize, salt: u64, f: impl Fn(u64) -> Vec<Fp> + Sync) -> Vec<Vec<Fp>> {
    let per = k.div_ceil(threads);
    std::thread::scope(|s| {
        let hs: Vec<_> = (0..threads)
            .map(|t| {
                let f = &f;
                s.spawn(move || {
                    (t * per..((t + 1) * per).min(k))
                        .map(|i| f(salt ^ ((i as u64 + 1) * 0x9E37_79B9_7F4A_7C15)))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        hs.into_iter().flat_map(|h| h.join().unwrap_or_else(|_| die("a worker panicked"))).collect()
    })
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (Some(kat), Some(out)) = (a.first(), a.get(1)) else {
        die("usage: zk_fri_rank <transcript-kat.json> <report.json> [threads=<n>]")
    };
    let threads = a
        .iter()
        .find_map(|s| s.strip_prefix("threads="))
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4));
    let mask_log: u32 = a
        .iter()
        .find_map(|s| s.strip_prefix("mask_log="))
        .and_then(|v| v.parse().ok())
        .unwrap_or(LOG_B)
        .min(LOG_B);
    let inst = instance(kat);
    let geo = geometry(&inst);
    let l0 = layer0_width(&geo);
    // Each column's opened rows, then N at z and g z: two F_p^2 values.
    let a_width = MASK.len() * geo.mask_points.len() + 4;

    // Enough samples to exceed every rank measured, with a margin.
    let probe = any_row(1, &inst, &geo);
    let f_width = probe.len();
    let k_any = f_width + 64;
    let k_mask = a_width + f_width + 64;
    println!(
        "instance  {} queries; FRI reveals {} base coordinates ({} at layer zero); mask openings {}",
        inst.positions.len(),
        f_width,
        l0,
        a_width
    );

    let t0 = std::time::Instant::now();
    let any = sample(k_any, threads, 0xA11, |s| any_row(s, &inst, &geo));
    let r_any = rank(&any, 0..f_width) - rank(&any, 0..l0);
    println!("simulator rank(F on ker layer0) = {r_any}   ({:?})", t0.elapsed());

    let t0 = std::time::Instant::now();
    let mask = sample(k_mask, threads, 0x3A5C, |s| mask_row(s, &inst, &geo, mask_log));
    let r_a = rank(&mask, 0..a_width);
    let r_mask = rank(&mask, 0..a_width + f_width) - r_a;
    println!("mask      rank(F on ker A)      = {r_mask}   (rank A = {r_a}, mask degree below 2^{mask_log}, {:?})", t0.elapsed());

    let equal = r_mask == r_any;
    println!("{}  the mask spans what the simulator samples", if equal { "PASS" } else { "FAIL" });
    let json = format!(
        "{{\n  \"artifact\": \"zk-fri-rank\",\n  \"transcript\": \"{kat}\",\n  \"queries\": {},\n  \
         \"fri_revealed\": {f_width},\n  \"layer0\": {l0},\n  \"mask_openings\": {a_width},\n  \"rank_mask_openings\": {r_a},\n  \
         \"rank_simulator\": {r_any},\n  \"rank_mask\": {r_mask},\n  \"samples\": [{k_any}, {k_mask}],\n  \"mask_log\": {mask_log},\n  \"pass\": {equal}\n}}\n",
        inst.positions.len()
    );
    std::fs::write(out, json).unwrap_or_else(|e| die(&format!("cannot write {out}: {e}")));
    if !equal {
        std::process::exit(1);
    }
}
