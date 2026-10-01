//! The kernel's add, subtract and multiply against the prover's own `Fp`, the field proofs use.

use nonos_stark::field::Fp;
use nox_field_kernel::{mul, reference, P};

/// A deterministic sweep, so a failure reproduces from its index.
fn sample(i: u64) -> u64 {
    let mut x = i.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(0x1234_5678_9ABC_DEF0);
    x ^= x >> 33;
    x = x.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
    x ^= x >> 29;
    x % P
}

fn edges() -> Vec<u64> {
    vec![0, 1, 2, P - 1, P - 2, 1 << 31, 1 << 32, (1 << 32) - 1, (1 << 32) + 1, 0xFFFF_FFFF, P / 2]
}

#[test]
fn the_multiply_agrees_with_the_prover_on_the_edges() {
    for a in edges() {
        for b in edges() {
            let theirs = (Fp::from_u64(a) * Fp::from_u64(b)).value();
            assert_eq!(mul(a, b), theirs, "mul({a}, {b})");
            assert_eq!(reference::mul(a, b), theirs, "reference::mul({a}, {b})");
        }
    }
}

/// A sweep catches a correction wrong only for products in a narrow range.
#[test]
fn the_multiply_agrees_with_the_prover_over_a_sweep() {
    for i in 0..20_000u64 {
        let (a, b) = (sample(i), sample(i ^ 0xFFFF));
        let theirs = (Fp::from_u64(a) * Fp::from_u64(b)).value();
        assert_eq!(mul(a, b), theirs, "mul at index {i}");
        assert_eq!(reference::mul(a, b), theirs, "reference::mul at index {i}");
    }
}

#[test]
fn the_ring_operations_agree_with_the_prover() {
    for i in 0..20_000u64 {
        let (a, b) = (sample(i), sample(i.wrapping_add(7)));
        let (x, y) = (Fp::from_u64(a), Fp::from_u64(b));
        assert_eq!(nox_field_kernel::add(a, b), (x + y).value(), "add at index {i}");
        assert_eq!(nox_field_kernel::sub(a, b), (x - y).value(), "sub at index {i}");
    }
}
