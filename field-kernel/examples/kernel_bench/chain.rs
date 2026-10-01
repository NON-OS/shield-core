//! A dependent chain, each multiply waiting on the last, the transform's inner shape. An
//! independent chain measures parallel retire rate, which flatters both versions equally.

use nox_field_kernel::{mul, P};
use std::time::Instant;

const ROUNDS: u64 = 50_000_000;

/// Time the chain and print nanoseconds per multiply.
pub fn run() {
    let mut x = 0x1234_5678_9ABC_DEF0u64 % P;
    let step = 0x9E37_79B9_7F4A_7C15u64 % P;

    let started = Instant::now();
    for _ in 0..ROUNDS {
        x = mul(x, step);
    }
    let elapsed = started.elapsed();

    let per = elapsed.as_secs_f64() / ROUNDS as f64;
    println!("\nchain       {ROUNDS} dependent multiplies");
    println!("elapsed     {elapsed:?}");
    println!("per multiply {:.3} ns", per * 1e9);
    // Printed so the loop cannot be optimised away.
    println!("final       {x}");
}
