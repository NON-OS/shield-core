use nox_field_kernel::{add, mul, sub, P};

/// A deterministic sweep, the same one the differential test uses.
fn sample(i: u64) -> u64 {
    let mut x = i.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(0x1234_5678_9ABC_DEF0);
    x ^= x >> 33;
    x = x.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
    x ^= x >> 29;
    x % P
}

/// Agreeing with a reference is not enough if the reference is wrong, so the
/// field laws are checked directly. These hold for any correct implementation
/// of this field, whichever multiply is in use.
#[test]
fn the_field_laws_hold_over_a_sweep() {
    for i in 0..5_000u64 {
        let (a, b, c) = (sample(i), sample(i + 1), sample(i + 2));
        assert_eq!(mul(a, b), mul(b, a), "multiply is not commutative at {i}");
        assert_eq!(mul(mul(a, b), c), mul(a, mul(b, c)), "multiply is not associative at {i}");
        assert_eq!(add(a, b), add(b, a), "add is not commutative at {i}");
        assert_eq!(mul(a, add(b, c)), add(mul(a, b), mul(a, c)), "no distribution at {i}");
        assert_eq!(mul(a, 1), a, "one is not the identity at {i}");
        assert_eq!(mul(a, 0), 0, "zero does not absorb at {i}");
        assert_eq!(sub(add(a, b), b), a, "subtract does not undo add at {i}");
    }
}

/// The identity the whole reduction rests on: 2^64 is 2^32 - 1 in this field.
#[test]
fn two_to_the_sixty_four_folds_to_epsilon() {
    let two32 = 1u64 << 32;
    assert_eq!(mul(two32, two32), (1u64 << 32) - 1);
}
