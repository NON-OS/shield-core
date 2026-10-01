// NONOS Operating System (AGPL-3.0-or-later)
//! The library on the command line, to time it on a device.
//!
//!     nox_bench <request.json> <seed.json> [out.json]
//!
//! Reads 512 random bytes from the operating system, proves through
//! `nox_prover::prove`, and prints the time and the proof size. Under WASI
//! this is the same code a browser runs.
//!
//! With `NOX_ENTROPY=<file>` the 512 random bytes come from that file, so the
//! proof is reproducible. `NOX_MEM=1` reports memory after each prover phase.
//!
//! With `NOX_CACHE=<file>`, proves from that periodic cache when the file
//! exists, and writes it from a full proof when it does not.

use std::io::Read;
use std::time::Instant;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (Some(req), Some(seed)) = (a.first(), a.get(1)) else {
        eprintln!("usage: nox_bench <request.json> <seed.json> [out.json]");
        std::process::exit(2)
    };
    let read = |p: &str| {
        std::fs::read_to_string(p).unwrap_or_else(|e| {
            eprintln!("cannot read {p}: {e}");
            std::process::exit(2)
        })
    };
    let mut entropy = [0u8; nox_prover::ENTROPY_BYTES];
    // NOX_ENTROPY names a file of fixed randomness: one seed, one proof, so a
    // prover change can be shown to leave the proof byte for byte the same.
    let source = std::env::var("NOX_ENTROPY").unwrap_or_else(|_| "/dev/urandom".to_string());
    let got = std::fs::File::open(&source).and_then(|mut f| f.read_exact(&mut entropy));
    if got.is_err() {
        eprintln!("no entropy source");
        std::process::exit(2)
    }
    let t = Instant::now();
    let cache = std::env::var("NOX_CACHE").ok();
    let stored = cache.as_deref().and_then(|c| std::fs::read(c).ok());
    let proved = match &stored {
        Some(top) => nox_prover::prove_with_cache(&read(req), &read(seed), &entropy, top),
        None => nox_prover::prove_keeping_cache(&read(req), &read(seed), &entropy).map(|(p, top)| {
            if let Some(c) = &cache {
                if let Err(e) = std::fs::write(c, &top) {
                    eprintln!("cannot write {c}: {e}");
                }
            }
            p
        }),
    };
    match proved {
        Ok(p) => {
            if stored.is_some() {
                println!("cache     periodic tree skipped");
            }
            println!("proved    {} bytes in {:?}, verified", p.bytes.len(), t.elapsed());
            println!(
                "grind     {} hashes, {:.2} of the mean 2^{}",
                p.grind_hashes,
                p.grind_hashes as f64 / (1u64 << nox_prover::GRIND_BITS) as f64,
                nox_prover::GRIND_BITS
            );
            if let Some(out) = a.get(2) {
                if let Err(e) = std::fs::write(out, nox_prover::to_json(&p)) {
                    eprintln!("cannot write {out}: {e}");
                    std::process::exit(2)
                }
            }
        }
        Err(why) => {
            eprintln!("refused   {why}");
            std::process::exit(1)
        }
    }
}
