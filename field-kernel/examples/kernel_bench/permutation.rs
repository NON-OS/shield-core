//! The permutation's arithmetic in the same proportions: eight x^7 S-boxes and a dense 8 by 8
//! multiply per round, 31 rounds. No round constants and no real MDS, only the multiply count
//! and dependency shape a kernel is judged on.

use nox_field_kernel::{add, mul, P};
use std::time::Instant;

const ROUNDS: usize = 31;
const PERMUTATIONS: u64 = 200_000;
const WIDTH: usize = 8;

/// x^7 by a four multiply addition chain, so the bench does not time a loop.
fn sbox(x: u64) -> u64 {
    let x2 = mul(x, x);
    let x3 = mul(x2, x);
    let x6 = mul(x3, x3);
    mul(x6, x)
}

pub fn run() {
    let mut state = [0u64; WIDTH];
    for (i, slot) in state.iter_mut().enumerate() {
        *slot = (0x9E37_79B9_7F4A_7C15u64.wrapping_mul(i as u64 + 1)) % P;
    }
    let matrix: [u64; WIDTH] = core::array::from_fn(|j| ((j as u64 + 2) * 0x1234_5679) % P);

    let started = Instant::now();
    for _ in 0..PERMUTATIONS {
        for _ in 0..ROUNDS {
            for slot in state.iter_mut() {
                *slot = sbox(*slot);
            }
            let mut next = [0u64; WIDTH];
            for (i, out) in next.iter_mut().enumerate() {
                for (j, value) in state.iter().enumerate() {
                    *out = add(*out, mul(*value, matrix[(i + j) % WIDTH]));
                }
            }
            state = next;
        }
    }
    let elapsed = started.elapsed();

    let muls = PERMUTATIONS * ROUNDS as u64 * ((WIDTH * 4 + WIDTH * WIDTH) as u64);
    println!("\npermutation {PERMUTATIONS} of {ROUNDS} rounds, {muls} multiplies");
    println!("elapsed     {elapsed:?}");
    println!("per multiply {:.3} ns", elapsed.as_secs_f64() / muls as f64 * 1e9);
    println!("per permutation {:.1} us", elapsed.as_secs_f64() / PERMUTATIONS as f64 * 1e6);
    println!("final       {}", state[0]);
}
