// NONOS Operating System (AGPL-3.0-or-later)
//! The chained query grind as a known answer, for anyone who searches nonces
//! on the prover's behalf (docs/12 Section 2.2): a GPU, a relayer, a port.
//!
//! Eight searches of 12 bits from `Transcript::new(b"nox grind kat")`, each
//! the smallest nonce, each absorbed before the next. A searcher that returns
//! these nonces and this state agrees with the prover bit for bit.

use crate::crypto::stark::transcript::Transcript;
use std::time::Instant;

const NONCES: [u64; 8] = [5165, 4308, 1076, 177, 11073, 2866, 3553, 1554];
const STATE: &str = "eefc8893ca1e0a00af361e11c0c4ca053d5ab789b4a3898ec623eccbcbe9f53e";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn the_chained_grind_is_the_pinned_answer() {
    let mut t = Transcript::new(b"nox grind kat");
    let nonces: Vec<u64> = (0..8).map(|_| t.grind(12)).collect();
    assert_eq!(nonces, NONCES);
    assert_eq!(hex(&t.state()), STATE);
}

/// Hashes a second on the CPU, from searches whose smallest nonces are the
/// work done: the figure a GPU is compared against, and the price of the
/// commit grind on a device. Threads from RAYON_NUM_THREADS.
#[test]
#[ignore = "bench: grinds about 2^30 hashes"]
fn print_the_cpu_grind_rate() {
    let mut t = Transcript::new(b"nox grind rate");
    let (mut hashes, start) = (0u64, Instant::now());
    for _ in 0..16 {
        hashes += t.grind(26) + 1;
    }
    let secs = start.elapsed().as_secs_f64();
    println!(
        "{:.1} MH/s over {hashes} hashes in {secs:.2} s, threads {}",
        hashes as f64 / secs / 1e6,
        std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "all".into())
    );
}
