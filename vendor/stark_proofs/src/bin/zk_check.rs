// NONOS Operating System (AGPL-3.0-or-later)
//! The two empirical zero-knowledge checks of docs/12-zero-knowledge.md, Section 4,
//! at the launch circuit.
//!
//!     zk_check <report.json> [pairs=1000] [threads=<n>]
//!
//! What a proof reveals of a column is the committed polynomial
//! `f + r * (x^t - 1)` at points off the trace domain: the query rows, the
//! out-of-domain frame, the FRI openings. This evaluates the committed
//! polynomials exactly as `recursion_assembly::inner::hide_at` and the prover
//! build them, at fixed points in F_p and F_p^2, for every region column and
//! every mask column, and asks two questions of the values.
//!
//! (i) One statement under `pairs` pairs of blinding seeds. Every value must
//!     differ between the two proofs of a pair, the two must be uncorrelated,
//!     and the values must be uniform.
//! (ii) Two different spends with the same values, under `pairs` seeds each.
//!     Per column, a two-sample Kolmogorov-Smirnov test must not tell them
//!     apart.
//!
//! Each check runs against a control without blinding first, and the control
//! must fail it: a check that cannot see an unblinded witness proves nothing
//! about a blinded one. The permutation product columns are not covered here;
//! the prover builds them from challenges, after the commitment these values
//! come from.

use stark_proofs::crypto::stark::air::{seed_from_entropy, Air, Permuted, RATE};
use stark_proofs::crypto::stark::field::{Fp, Fp2};
use stark_proofs::crypto::stark::fri::root_of_unity;
use stark_proofs::crypto::stark::poly::eval_cols_on_subgroup_ext;
use stark_proofs::host::die;
use stark_proofs::recursion_assembly::inner::{hasher, hide_at};
use stark_proofs::shield::join::{address_from_u64, join_split_at, JoinSplit, Settle, Spend};
use stark_proofs::shield::key::Break;
use stark_proofs::shield::member::TREE_DEPTH;
use stark_proofs::shield::note::Note;
use stark_proofs::shield::test::fixture::{owned, plain, secret};
use stark_proofs::shield_params::direct;
use std::io::Read;

/// Fixed evaluation points: four in F_p^2 and four in F_p, off the trace
/// domain with overwhelming probability, from a fixed stream so every run
/// asks about the same points.
fn points() -> Vec<Fp2> {
    let mut s = 0x243f_6a88_85a3_08d3u64;
    let mut next = || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        Fp::from_u64(s)
    };
    let mut v: Vec<Fp2> = (0..4)
        .map(|_| Fp2 {
            c0: next(),
            c1: next(),
        })
        .collect();
    v.extend((0..4).map(|_| Fp2::from_base(next())));
    v
}

/// A spend at the launch depth: one owned note of 1000 and one of 500, paid
/// out as 1200 and 300. `who` picks the secrets and the output keys, so two
/// values of `who` are two different spends with one value split.
fn spend(who: u64) -> JoinSplit {
    let sks = [secret(10 * who + 1), secret(10 * who + 2)];
    let notes = [owned(sks[0], who, 1000), owned(sks[1], who + 1, 500)];
    let outs: [Note; 2] = [plain(20 + who, 1200), plain(30 + who, 300)];
    join_split_at(
        TREE_DEPTH,
        [
            Spend {
                note: &notes[0],
                sk: sks[0],
            },
            Spend {
                note: &notes[1],
                sk: sks[1],
            },
        ],
        [&outs[0], &outs[1]],
        0,
        0,
        Break::None,
        Settle {
            not_before: 0,
            clearing_price: 0,
            recipient: address_from_u64(0),
            fee_recipient: [0; 20],
        },
        None,
    )
}

/// One spend and what is fixed about it: its region columns' interpolants at
/// the points, which no seed changes.
struct Subject {
    js: JoinSplit,
    width: usize,
    region: usize,
    mask: usize,
    t: usize,
    g: Fp,
    region_at: Vec<Vec<Fp2>>,
}

impl Subject {
    fn new(who: u64, pts: &[Fp2]) -> Subject {
        let js = spend(who);
        let width = js.wired.trace_width();
        let region = js.wired.region_width();
        let mask = js.wired.wired().mask_columns();
        let t = 1usize << js.wired.log_trace_len();
        let g = root_of_unity(t.trailing_zeros());
        let cols: Vec<Vec<Fp>> = (0..region)
            .map(|c| (0..t).map(|r| js.witness[r * width + c]).collect())
            .collect();
        let region_at = pts
            .iter()
            .map(|&z| eval_cols_on_subgroup_ext(g, t, &cols, z))
            .collect();
        Subject {
            js,
            width,
            region,
            mask,
            t,
            g,
            region_at,
        }
    }

    /// The columns this checks: every region column, then every mask column.
    fn columns(&self) -> Vec<usize> {
        (0..self.region)
            .chain(self.width - self.mask..self.width)
            .collect()
    }

    /// The committed values at every point, column by column, as the prover
    /// would commit them under `seed`; `None` commits the witness unblinded
    /// with empty mask columns, the control.
    fn values(&mut self, seed: Option<&[Fp; RATE]>, pts: &[Fp2]) -> Vec<Vec<Fp2>> {
        let blind = match seed {
            Some(s) => hide_at(&hasher(), &mut self.js, s, direct::N_QUERIES, 4),
            None => Vec::new(),
        };
        let mask_cols: Vec<Vec<Fp>> = (self.width - self.mask..self.width)
            .map(|c| {
                (0..self.t)
                    .map(|r| {
                        if seed.is_some() {
                            self.js.witness[r * self.width + c]
                        } else {
                            Fp::ZERO
                        }
                    })
                    .collect()
            })
            .collect();
        let cols = self.columns();
        cols.iter()
            .enumerate()
            .map(|(k, &c)| {
                pts.iter()
                    .enumerate()
                    .map(|(j, &z)| {
                        let f = if k < self.region {
                            self.region_at[j][c]
                        } else {
                            eval_cols_on_subgroup_ext(
                                self.g,
                                self.t,
                                &mask_cols[k - self.region..k - self.region + 1],
                                z,
                            )[0]
                        };
                        match blind.get(c) {
                            Some(r) => f + eval_ext(r, z) * (z.pow(self.t as u64) - Fp2::ONE),
                            None => f,
                        }
                    })
                    .collect()
            })
            .collect()
    }
}

fn eval_ext(coeffs: &[Fp], z: Fp2) -> Fp2 {
    let mut acc = Fp2::ZERO;
    for c in coeffs.iter().rev() {
        acc = acc * z + Fp2::from_base(*c);
    }
    acc
}

/// A value in [0, 1): its place in the field.
fn unit(v: Fp) -> f64 {
    v.to_u64() as f64 / 18446744069414584321.0
}

/// The base-field samples of one proof's values: both halves of an F_p^2
/// value, the one half of an F_p value.
fn samples(vals: &[Vec<Fp2>], pts: &[Fp2]) -> Vec<Vec<f64>> {
    vals.iter()
        .map(|col| {
            col.iter()
                .zip(pts)
                .flat_map(|(v, z)| {
                    if z.c1 == Fp::ZERO {
                        vec![unit(v.c0)]
                    } else {
                        vec![unit(v.c0), unit(v.c1)]
                    }
                })
                .collect()
        })
        .collect()
}

fn pearson(a: &[f64], b: &[f64]) -> f64 {
    let n = a.len() as f64;
    let (ma, mb) = (a.iter().sum::<f64>() / n, b.iter().sum::<f64>() / n);
    let (mut sab, mut saa, mut sbb) = (0.0, 0.0, 0.0);
    for (x, y) in a.iter().zip(b) {
        sab += (x - ma) * (y - mb);
        saa += (x - ma) * (x - ma);
        sbb += (y - mb) * (y - mb);
    }
    if saa == 0.0 || sbb == 0.0 {
        return 1.0;
    }
    sab / (saa * sbb).sqrt()
}

fn chi_square(u: &[f64], buckets: usize) -> f64 {
    let mut count = vec![0usize; buckets];
    for &x in u {
        count[((x * buckets as f64) as usize).min(buckets - 1)] += 1;
    }
    let e = u.len() as f64 / buckets as f64;
    count.iter().map(|&c| (c as f64 - e).powi(2) / e).sum()
}

/// The two-sample Kolmogorov-Smirnov statistic.
fn ks(a: &mut [f64], b: &mut [f64]) -> f64 {
    a.sort_by(|x, y| x.total_cmp(y));
    b.sort_by(|x, y| x.total_cmp(y));
    let (mut i, mut j, mut d) = (0usize, 0usize, 0f64);
    while i < a.len() && j < b.len() {
        if a[i] <= b[j] {
            i += 1;
        } else {
            j += 1;
        }
        d = d.max((i as f64 / a.len() as f64 - j as f64 / b.len() as f64).abs());
    }
    d
}

fn os_seed() -> [Fp; RATE] {
    let mut buf = [0u8; 64];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .unwrap_or_else(|e| die(&format!("no entropy source: {e}")));
    seed_from_entropy(&buf).unwrap_or_else(|| die("no seed from the entropy"))
}

/// Per seed, the samples of `who`'s values, column by column. Threads each
/// hold their own copy of the spend.
fn run(who: u64, n: usize, threads: usize, pts: &[Fp2]) -> Vec<Vec<Vec<f64>>> {
    let per = n.div_ceil(threads);
    std::thread::scope(|s| {
        let hs: Vec<_> = (0..threads)
            .map(|k| {
                s.spawn(move || {
                    let mut sub = Subject::new(who, pts);
                    let lo = k * per;
                    let hi = ((k + 1) * per).min(n);
                    (lo..hi)
                        .map(|_| samples(&sub.values(Some(&os_seed()), pts), pts))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        hs.into_iter()
            .flat_map(|h| h.join().unwrap_or_else(|_| die("a worker panicked")))
            .collect()
    })
}

struct Verdict {
    name: &'static str,
    value: f64,
    bound: f64,
    pass: bool,
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let Some(out) = a.first().filter(|s| !s.contains('=')).cloned() else {
        die("usage: zk_check <report.json> [pairs=1000] [threads=<n>]")
    };
    let arg = |k: &str, d: usize| {
        a.iter()
            .find_map(|s| s.strip_prefix(k))
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    };
    let pairs = arg("pairs=", 1000);
    let threads = arg(
        "threads=",
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4),
    );
    let pts = points();

    let mut probe = Subject::new(1, &pts);
    let cols = probe.columns().len();
    println!(
        "circuit   width {} region {} mask {} rows {}; checking {cols} columns at {} points",
        probe.width,
        probe.region,
        probe.mask,
        probe.t,
        pts.len()
    );

    // Controls: no blinding. The same statement twice is the same values,
    // and two spends differ in some column outright.
    let ca = samples(&probe.values(None, &pts), &pts);
    let cb = samples(&probe.values(None, &pts), &pts);
    let control_equal = ca
        .iter()
        .flatten()
        .zip(cb.iter().flatten())
        .filter(|(x, y)| x == y)
        .count();
    let mut other = Subject::new(2, &pts);
    let co = samples(&other.values(None, &pts), &pts);
    let control_differs = ca.iter().zip(&co).filter(|(x, y)| x != y).count();
    println!("control   unblinded: {control_equal} of {} values repeat between two proofs; {control_differs} of {cols} columns differ between the two spends", ca.iter().flatten().count());
    if control_equal == 0 || control_differs == 0 {
        die("the control is not detectable: the checks below would prove nothing");
    }

    let t0 = std::time::Instant::now();
    let a1 = run(1, pairs, threads, &pts);
    let a2 = run(1, pairs, threads, &pts);
    let b = run(2, pairs, threads, &pts);
    println!(
        "sampled   {} proofs' values in {:?}",
        3 * pairs,
        t0.elapsed()
    );

    // (i) the same statement under two seeds
    let x: Vec<f64> = a1.iter().flatten().flatten().copied().collect();
    let y: Vec<f64> = a2.iter().flatten().flatten().copied().collect();
    let equal = x.iter().zip(&y).filter(|(p, q)| p == q).count();
    let r = pearson(&x, &y);
    let r_bound = 5.0 / (x.len() as f64).sqrt();
    let buckets = 64;
    let chi = chi_square(&x, buckets);
    // Five standard deviations above the mean of chi-square on 63 degrees.
    let chi_bound = (buckets - 1) as f64 + 5.0 * (2.0 * (buckets - 1) as f64).sqrt();

    // (ii) two spends, column by column
    let n_col = a1[0][0].len();
    let mut d_max = 0f64;
    let mut worst = 0usize;
    for c in 0..cols {
        let mut pa: Vec<f64> = a1.iter().flat_map(|p| p[c].iter().copied()).collect();
        let mut pb: Vec<f64> = b.iter().flat_map(|p| p[c].iter().copied()).collect();
        let d = ks(&mut pa, &mut pb);
        if d > d_max {
            d_max = d;
            worst = c;
        }
    }
    // Bonferroni over the columns at an overall 1e-4.
    let m = (pairs * n_col) as f64;
    let alpha = 1e-4 / cols as f64;
    let d_bound = (-0.5 * (alpha / 2.0).ln()).sqrt() * (2.0 / m).sqrt();

    let verdicts = [
        Verdict {
            name: "(i) values repeated between the two proofs of a pair",
            value: equal as f64,
            bound: 0.0,
            pass: equal == 0,
        },
        Verdict {
            name: "(i) correlation between the two proofs of a pair",
            value: r,
            bound: r_bound,
            pass: r.abs() < r_bound,
        },
        Verdict {
            name: "(i) chi-square of the values over 64 buckets",
            value: chi,
            bound: chi_bound,
            pass: chi < chi_bound,
        },
        Verdict {
            name: "(ii) largest KS distance between the two spends, any column",
            value: d_max,
            bound: d_bound,
            pass: d_max < d_bound,
        },
    ];
    let mut ok = true;
    for v in &verdicts {
        println!(
            "{}  {:<62} {:>12.6}  bound {:.6}",
            if v.pass { "PASS" } else { "FAIL" },
            v.name,
            v.value,
            v.bound
        );
        ok &= v.pass;
    }
    println!(
        "          worst KS column {worst}, {} samples per column per spend",
        pairs * n_col
    );

    let rows: Vec<String> = verdicts
        .iter()
        .map(|v| {
            format!(
                "    {{\"check\": \"{}\", \"value\": {}, \"bound\": {}, \"pass\": {}}}",
                v.name, v.value, v.bound, v.pass
            )
        })
        .collect();
    let json = format!(
        "{{\n  \"artifact\": \"zk-check\",\n  \"point\": [{}, {}, {}],\n  \"pairs\": {pairs},\n  \"columns\": {cols},\n  \
         \"points\": {},\n  \"samples_per_proof\": {},\n  \"control_repeats\": {control_equal},\n  \
         \"control_columns_differing\": {control_differs},\n  \"not_covered\": \"permutation product columns\",\n  \
         \"checks\": [\n{}\n  ],\n  \"pass\": {ok}\n}}\n",
        direct::N_QUERIES,
        direct::GRIND_BITS,
        direct::EXTRA_BLOWUP_BITS,
        pts.len(),
        x.len() / pairs,
        rows.join(",\n")
    );
    std::fs::write(&out, json).unwrap_or_else(|e| die(&format!("cannot write {out}: {e}")));
    println!("wrote {out}");
    if !ok {
        std::process::exit(1);
    }
}
