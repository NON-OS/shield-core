use nox_field_kernel::reference;
use nox_field_kernel::{add, butterfly, mul, sub, P};

/// A deterministic sweep, so a failure is reproducible from its index alone.
fn sample(i: u64) -> u64 {
    let mut x = i.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(0x1234_5678_9ABC_DEF0);
    x ^= x >> 33;
    x = x.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
    x ^= x >> 29;
    x % P
}

/// The values a field bug hides behind: the ends of the range, the modulus
/// boundary, and the powers of two the reduction splits on.
fn edges() -> Vec<u64> {
    vec![
        0,
        1,
        2,
        P - 1,
        P - 2,
        1 << 31,
        1 << 32,
        (1 << 32) - 1,
        (1 << 32) + 1,
        0xFFFF_FFFF,
        0xFFFF_FFFF_0000_0000,
        P / 2,
        P / 2 + 1,
    ]
}

#[test]
fn the_multiply_agrees_with_its_reference_on_the_edges() {
    for a in edges() {
        for b in edges() {
            assert_eq!(mul(a, b), reference::mul(a, b), "mul({a}, {b})");
        }
    }
}

#[test]
fn the_multiply_agrees_with_its_reference_over_a_sweep() {
    for i in 0..20_000u64 {
        let (a, b) = (sample(i), sample(i ^ 0xFFFF));
        assert_eq!(mul(a, b), reference::mul(a, b), "mul at index {i}");
    }
}

#[test]
fn every_result_is_canonical() {
    for i in 0..20_000u64 {
        let (a, b) = (sample(i), sample(i.wrapping_add(7)));
        for value in [mul(a, b), add(a, b), sub(a, b)] {
            assert!(value < P, "a result at index {i} left the field: {value}");
        }
    }
}

#[test]
fn a_butterfly_is_the_pair_of_its_halves() {
    for i in 0..2_000u64 {
        let (a, b) = (sample(i), sample(i * 3 + 1));
        assert_eq!(butterfly(a, b), (add(a, b), sub(a, b)));
    }
}
