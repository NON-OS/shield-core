// NONOS Operating System (AGPL-3.0-or-later)
//! Where a launch proof's time goes, phase by phase, as the wallet proves it:
//! from the bundled periodic cache, the pinned transfer, the process's own peak
//! memory. One run per process, threads from RAYON_NUM_THREADS:
//!
//!     NOX_PROFILE_CACHE=<periodic.top> RAYON_NUM_THREADS=6 \
//!         cargo test --release --features parallel --lib profile -- --ignored --nocapture
//!
//! `NOX_PROFILE_DIR` names another vector, the 37-word one under
//! `spec/wallet-vectors-not-before/transfer-eth` in the `not_before` build.

use crate::api::{prove_with, Options, Phase};
use std::sync::Mutex;
use std::time::Instant;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../spec/wallet-vectors/transfer-eth");

fn read(name: &str) -> String {
    let dir = std::env::var("NOX_PROFILE_DIR").unwrap_or_else(|_| DIR.into());
    std::fs::read_to_string(format!("{dir}/{name}")).expect("a pinned vector file")
}

fn peak_mb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmHWM:")).map(str::to_string))
        .and_then(|l| l.split_whitespace().nth(1).and_then(|k| k.parse::<u64>().ok()))
        .map_or(0, |kb| kb / 1024)
}

#[test]
#[ignore = "profile: set NOX_PROFILE_CACHE, one run per process"]
fn profile_the_launch_proof_by_phase() {
    let cache = std::fs::read(std::env::var("NOX_PROFILE_CACHE").expect("NOX_PROFILE_CACHE")).expect("the cache");
    let hex = read("entropy.hex");
    let hex = hex.trim();
    let entropy: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex"))
        .collect();
    let marks: Mutex<Vec<(Phase, Instant)>> = Mutex::new(Vec::new());
    let record = |p: Phase, _f: f32| {
        if let Ok(mut m) = marks.lock() {
            m.push((p, Instant::now()));
        }
    };
    let opts = Options { cache: Some(&cache), progress: Some(&record), cancel: None };
    let start = Instant::now();
    let (proof, _) = prove_with(&read("request.json"), &read("seed.json"), &entropy, &opts).expect("proves");
    let total = start.elapsed().as_secs_f64();
    let marks = marks.into_inner().unwrap_or_default();
    let mut last = start;
    println!("phase | seconds | share");
    for (p, t) in &marks {
        let s = t.duration_since(last).as_secs_f64();
        println!("{p:?} | {s:.2} | {:.1}%", 100.0 * s / total);
        last = *t;
    }
    println!(
        "total {total:.2} s, {} bytes, peak {} MB, threads {}",
        proof.bytes.len(),
        peak_mb(),
        std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "all".into())
    );
}
