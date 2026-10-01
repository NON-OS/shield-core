// NONOS Operating System (AGPL-3.0-or-later)
//! The wallet API end to end on a real spend.
//!
//!     nox_api_check <request.json> <seed.json> <periodic.top>
//!
//! Proves with progress reported, verifies the proof with `verify`, checks
//! that a flipped public word is refused, and that a proof cancelled after
//! the composition phase returns `Error::Cancelled`. Exits nonzero on any
//! departure.

use nox_prover::{prove_with, verify, Error, Options, Phase, ENTROPY_BYTES};
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

fn entropy() -> Vec<u8> {
    let mut b = vec![0u8; ENTROPY_BYTES];
    if std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).is_err() {
        eprintln!("no entropy source");
        std::process::exit(2);
    }
    b
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (Some(r), Some(s), Some(c)) = (a.first(), a.get(1), a.get(2)) else {
        eprintln!("usage: nox_api_check <request.json> <seed.json> <periodic.top>");
        std::process::exit(2)
    };
    let read = |p: &str| std::fs::read_to_string(p).unwrap_or_else(|e| panic_free_exit(&format!("{p}: {e}")));
    let (request, seed) = (read(r), read(s));
    let cache = std::fs::read(c).unwrap_or_else(|e| panic_free_exit(&format!("{c}: {e}")));
    let mut ok = true;

    let seen: Mutex<Vec<(Phase, f32)>> = Mutex::new(Vec::new());
    let progress = |p: Phase, f: f32| {
        println!("progress  {:>5.1}%  {p:?}", f * 100.0);
        if let Ok(mut v) = seen.lock() {
            v.push((p, f));
        }
    };
    let t = std::time::Instant::now();
    let opts = Options { cache: Some(&cache), progress: Some(&progress), cancel: None };
    match prove_with(&request, &seed, &entropy(), &opts) {
        Ok((proof, publics)) => {
            println!("proved    {} bytes in {:?}", proof.bytes.len(), t.elapsed());
            let phases = seen.lock().map(|v| v.clone()).unwrap_or_default();
            let monotone = phases.windows(2).all(|w| w[0].1 <= w[1].1);
            let ends = phases.last().map(|p| p.0 == Phase::Verified && p.1 == 1.0).unwrap_or(false);
            println!("{}  {} progress reports, rising, ending at Verified", if monotone && ends { "PASS" } else { "FAIL" }, phases.len());
            ok &= monotone && ends;
            let v = verify(&proof.bytes, &publics, &cache);
            println!("{}  verify accepts the proof: {v:?}", if v.is_ok() { "PASS" } else { "FAIL" });
            ok &= v.is_ok();
            let mut bent = publics;
            bent[24] = bent[24].wrapping_add(1);
            let v = verify(&proof.bytes, &bent, &cache);
            let refused = matches!(v, Err(Error::NotVerified(_)));
            println!("{}  verify refuses a flipped public word", if refused { "PASS" } else { "FAIL" });
            ok &= refused;
        }
        Err(e) => {
            println!("FAIL  prove_with: {e}");
            ok = false;
        }
    }

    let flag = AtomicBool::new(false);
    let stop_after = |p: Phase, _f: f32| {
        if p == Phase::Composition {
            flag.store(true, Ordering::Relaxed);
        }
    };
    let opts = Options { cache: Some(&cache), progress: Some(&stop_after), cancel: Some(&flag) };
    let t = std::time::Instant::now();
    let r = prove_with(&request, &seed, &entropy(), &opts);
    let cancelled = matches!(r, Err(Error::Cancelled));
    println!("{}  cancelled after the composition phase in {:?}: {:?}", if cancelled { "PASS" } else { "FAIL" }, t.elapsed(), r.err());
    ok &= cancelled;

    if !ok {
        std::process::exit(1);
    }
}

fn panic_free_exit(why: &str) -> ! {
    eprintln!("cannot read {why}");
    std::process::exit(2)
}
