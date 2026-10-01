// NONOS Operating System (AGPL-3.0-or-later)
//! Hypothesis H6 of the zero-knowledge theorem, measured on a real proof with
//! the mask pair opened as one F_p^2 value.
//!
//!     zk_h6 <transcript-kat.json> <report.json> [threads=<n>]
//!
//! The mask pair is `N = M_a + X M_b`, a uniform F_p^2 polynomial of degree
//! below `B`, and everything the proof opens of it is F_p^2-linear in `N`: its
//! values at the 152 opened rows, and at `z` and `g z`. The masks that pass
//! those openings are exactly `N = W (x - z)(x - g z) R`, with `W` vanishing on
//! the opened rows and `R` any F_p^2 polynomial of degree below `B - 154`.
//! This samples such masks and measures, over F_p^2, the rank of what FRI then
//! reveals beyond layer zero. The theorem needs it equal to the simulator's,
//! 664 F_p^2 values when no queries collide.

use stark_proofs::crypto::stark::field::{Fp, Fp2};
use stark_proofs::crypto::stark::fri::root_of_unity;
use stark_proofs::host::{die, read_text};

const LOG_N: u32 = 23;
const LOG_B: u32 = 17;
const LOG_T: u32 = 13;
const WIDTH: usize = 44;
const PAIR_A: usize = 42;
const LAYERS: usize = 4;
const RADIX: usize = 4;

struct Instance {
    z: Fp2,
    alpha: Fp2,
    betas: Vec<Fp2>,
    positions: Vec<usize>,
}

fn instance(path: &str) -> Instance {
    let text = read_text(path);
    let (mut fp2, mut idx, mut half) = (Vec::new(), Vec::new(), None::<u64>);
    for line in text.lines() {
        let op = |name: &str| line.contains(&format!("\"op\": \"{name}\""));
        let word = || -> u64 {
            let at = line.find("\"word\": \"").unwrap_or_else(|| die("a draw without its word")) + 9;
            u64::from_str_radix(&line[at..at + 16], 16).unwrap_or_else(|_| die("a word that is not hex"))
        };
        if op("challenge_fp2_c0") {
            half = Some(word());
        } else if op("challenge_fp2_c1") {
            let c0 = half.take().unwrap_or_else(|| die("half an extension draw"));
            fp2.push(Fp2::new(Fp::from_u64(c0), Fp::from_u64(word())));
        } else if op("challenge_index") {
            idx.push((word() as usize) & ((1usize << LOG_N) - 1));
        }
    }
    if fp2.len() != 5 + LAYERS {
        die("not a launch transcript vector");
    }
    Instance { z: fp2[3], alpha: fp2[4], betas: fp2[5..].to_vec(), positions: idx }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn fp2(&mut self) -> Fp2 {
        Fp2::new(Fp::from_u64(self.next()), Fp::from_u64(self.next()))
    }
}

fn eval_at_base(c: &[Fp2], x: Fp) -> Fp2 {
    c.iter().rev().fold(Fp2::ZERO, |a, &v| a.mul_base(x) + v)
}

/// `(P(x) - P(z)) / (x - z)`.
fn quotient(p: &[Fp2], z: Fp2) -> Vec<Fp2> {
    let mut q = vec![Fp2::ZERO; p.len() - 1];
    let mut acc = Fp2::ZERO;
    for i in (1..p.len()).rev() {
        acc = acc * z + p[i];
        q[i - 1] = acc;
    }
    q
}

/// `p * (x - r)`.
fn times_linear(p: &[Fp2], r: Fp2) -> Vec<Fp2> {
    let mut out = vec![Fp2::ZERO; p.len() + 1];
    for (i, &c) in p.iter().enumerate() {
        out[i + 1] = out[i + 1] + c;
        out[i] = out[i] - c * r;
    }
    out
}

fn fold(c: &[Fp2], beta: Fp2) -> Vec<Fp2> {
    let pw = [Fp2::ONE, beta, beta * beta, beta * beta * beta];
    c.chunks(RADIX).map(|q| q.iter().zip(pw).fold(Fp2::ZERO, |a, (v, p)| a + *v * p)).collect()
}

/// Rank over F_p^2.
fn rank(rows: &[Vec<Fp2>]) -> usize {
    let mut basis: Vec<(usize, Vec<Fp2>)> = Vec::new();
    for r in rows {
        let mut v = r.clone();
        for (p, b) in &basis {
            let f = v[*p];
            if f != Fp2::ZERO {
                for (x, y) in v.iter_mut().zip(b) {
                    *x = *x - f * *y;
                }
            }
        }
        if let Some(p) = v.iter().position(|x| *x != Fp2::ZERO) {
            let inv = v[p].inv();
            for x in v.iter_mut() {
                *x = *x * inv;
            }
            basis.push((p, v));
        }
    }
    basis.len()
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (Some(kat), Some(out)) = (a.first(), a.get(1)) else {
        die("usage: zk_h6 <transcript-kat.json> <report.json> [threads=<n>]")
    };
    let threads = a
        .iter()
        .find_map(|s| s.strip_prefix("threads="))
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4));
    let inst = instance(kat);
    let (n, b) = (1usize << LOG_N, 1usize << LOG_B);
    let omega = root_of_unity(LOG_N);
    let g = root_of_unity(LOG_T);
    let shift = Fp::from_u64(7);
    let layer_points: Vec<Vec<Fp>> = (0..LAYERS)
        .map(|m| {
            let quarter = (n >> (2 * m)) / RADIX;
            let (w, s) = (omega.pow(1u64 << (2 * m)), shift.pow(1u64 << (2 * m)));
            inst.positions
                .iter()
                .flat_map(|&p| (0..RADIX).map(move |r| s * w.pow((p % quarter + r * quarter) as u64)))
                .collect()
        })
        .collect();
    // W: vanishing on every opened row and its successor.
    let mut w = vec![Fp2::ONE];
    for &x in &layer_points[0] {
        for r in [x, x * g] {
            w = times_linear(&w, Fp2::from_base(r));
        }
    }
    let zs = [inst.z, inst.z.mul_base(g)];
    let mut base = w.clone();
    for &zk in &zs {
        base = times_linear(&base, zk);
    }
    let r_len = b - base.len() + 1;
    let coeff = [inst.alpha.pow(PAIR_A as u64), inst.alpha.pow((WIDTH + PAIR_A) as u64)];

    // One row: FRI beyond layer zero for N = base * R, R random.
    let row = |seed: u64| -> Vec<Fp2> {
        let mut rng = Rng(seed | 1);
        let r: Vec<Fp2> = (0..r_len).map(|_| rng.fp2()).collect();
        let mut nn = vec![Fp2::ZERO; b];
        for (i, &bi) in base.iter().enumerate() {
            for (j, &rj) in r.iter().enumerate() {
                nn[i + j] = nn[i + j] + bi * rj;
            }
        }
        let mut d = vec![Fp2::ZERO; b - 1];
        for (k, &zk) in zs.iter().enumerate() {
            for (acc, q) in d.iter_mut().zip(quotient(&nn, zk)) {
                *acc = *acc + coeff[k] * q;
            }
        }
        let mut out = Vec::new();
        let mut cur = d;
        for (m, points) in layer_points.iter().enumerate().take(LAYERS) {
            if m > 0 {
                out.extend(points.iter().map(|&x| eval_at_base(&cur, x)));
            }
            cur = fold(&cur, inst.betas[m]);
        }
        out.extend(cur);
        out
    };
    let width = row(1).len();
    let k = width + 32;
    let per = k.div_ceil(threads);
    let t0 = std::time::Instant::now();
    let rows: Vec<Vec<Fp2>> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..threads)
            .map(|t| {
                let row = &row;
                s.spawn(move || (t * per..((t + 1) * per).min(k)).map(|i| row(0xB6 ^ ((i as u64 + 1) * 0x9E37_79B9))).collect::<Vec<_>>())
            })
            .collect();
        hs.into_iter().flat_map(|h| h.join().unwrap_or_else(|_| die("a worker panicked"))).collect()
    });
    let r = rank(&rows);
    println!("H6        F_p^2 rank of FRI beyond layer zero over N = W (x-z)(x-gz) R: {r} of {width} coordinates, {k} samples, {:?}", t0.elapsed());
    std::fs::write(
        out,
        format!("{{\n  \"artifact\": \"zk-h6\",\n  \"transcript\": \"{kat}\",\n  \"field\": \"F_p^2\",\n  \"coordinates\": {width},\n  \"rank\": {r},\n  \"samples\": {k}\n}}\n"),
    )
    .unwrap_or_else(|e| die(&format!("cannot write {out}: {e}")));
}
