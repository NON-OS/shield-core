// NONOS Operating System (AGPL-3.0-or-later)
//! What rate 2^-7 costs the prover against the launch's 2^-6: the pinned
//! transfer proved from a periodic cache, as a phone proves, timed, with the
//! process's peak resident memory.
//!
//! One configuration per process, so the peak is that configuration's own:
//!
//!     NOX_BENCH_EXTRA=5|6 NOX_BENCH_CACHE=<file> RAYON_NUM_THREADS=6 \
//!         cargo test --release --features parallel --lib rate_bench -- --ignored --nocapture
//!
//! The first run at an extra builds the full periodic tree and writes the
//! cache; run it again to time the proof from the cache. The query grind is
//! held at 8 bits because v2 buys it from a helper (docs/12 Section 2.2); the
//! commit grind is the launch transcript's own.

use crate::crypto::stark::air::{
    stark_prove_ext_rounds, stark_prove_ext_rounds_top_observed, stark_verify_ext_rounds_why,
};
use crate::crypto::stark::field::Fp;
use crate::crypto::stark::fri::FRI_FOLD_LOG;
use crate::crypto::stark::merkle::TreeTop;
use crate::host::{build_parts_with, Entropy};
use crate::recursion_assembly::inner::{hasher, hide_at};
use crate::shield::batch::assemble;
use crate::shield::join::JoinSplit;
use crate::shield_params::direct;
use std::time::Instant;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../spec/wallet-vectors/transfer-eth");
const QUERY_GRIND: u32 = 8;
const CUT: usize = 6;

fn read(name: &str) -> String {
    std::fs::read_to_string(format!("{DIR}/{name}")).expect("a pinned vector file")
}

fn entropy() -> Vec<u8> {
    let hex = read("entropy.hex");
    let hex = hex.trim();
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

/// The process's peak resident set, from the kernel.
fn peak_mb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmHWM:")).map(str::to_string))
        .and_then(|l| l.split_whitespace().nth(1).and_then(|k| k.parse::<u64>().ok()))
        .map_or(0, |kb| kb / 1024)
}

#[test]
#[ignore = "bench: set NOX_BENCH_EXTRA and NOX_BENCH_CACHE, one configuration per process"]
fn rate_bench() {
    let extra: u32 = std::env::var("NOX_BENCH_EXTRA").ok().and_then(|v| v.parse().ok()).unwrap_or(5);
    let cache_path = std::env::var("NOX_BENCH_CACHE").expect("NOX_BENCH_CACHE");
    let q = direct::N_QUERIES;

    let ent = entropy();
    let mut e = Entropy::new(&ent);
    let (parts, _) = {
        let mut words = |n: usize| e.words(n);
        build_parts_with(&read("request.json"), &read("seed.json"), &mut words).expect("the pinned request")
    };
    let mut b = assemble(vec![parts.parts]);
    let intent = b.intents.pop().expect("one statement");
    let mut js = JoinSplit { wired: b.wired, witness: b.witness, intent };
    let h = hasher();
    let w = e.words(4).expect("entropy");
    let blind = hide_at(&h, &mut js, &[w[0], w[1], w[2], w[3]], q, 1usize << FRI_FOLD_LOG);
    let publics: Vec<Fp> = js.intent.clone();
    let mut witness = js.witness;

    let cached = std::fs::read(&cache_path).ok().and_then(|b| TreeTop::from_bytes(&b));
    let t = Instant::now();
    let (rounds, air, root, how) = match cached {
        Some(top) => {
            let (rounds, air) = stark_prove_ext_rounds_top_observed(
                js.wired, &mut witness, q, QUERY_GRIND, extra, &publics, &top, &blind, &|_| true,
            )
            .expect("the cache is this circuit's at this rate");
            (rounds, air, top.root(), "from the cache")
        }
        None => {
            let (rounds, tree, air) =
                stark_prove_ext_rounds(js.wired, &mut witness, q, QUERY_GRIND, extra, &publics, None, &blind)
                    .expect("proves");
            let top = TreeTop::of(&tree, CUT).expect("tall enough");
            std::fs::write(&cache_path, top.to_bytes()).expect("write the cache");
            (rounds, air, tree.root(), "building the full tree, cache written")
        }
    };
    let took = t.elapsed();
    drop(witness);
    stark_verify_ext_rounds_why(air, &rounds, q, QUERY_GRIND, extra, &root, &publics).expect("the proof verifies");
    println!(
        "rate 2^-{}: proved {how} in {:.2} s, peak {} MB, threads {}",
        1 + extra,
        took.as_secs_f64(),
        peak_mb(),
        std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "all".into())
    );
}
