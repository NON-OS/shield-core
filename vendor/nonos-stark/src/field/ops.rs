// NONOS Operating System (AGPL-3.0-or-later)

//! The field ring operations. Multiplication reduces through the special form
//! of the modulus rather than a division: `P = 2^64 - 2^32 + 1`, so `2^64` is
//! `EPSILON` and `2^96` is `-1` in the field, and the 128 bit product folds
//! back with two shifts, one multiply and two conditional corrections.

use super::element::{Fp, EPSILON, P};

impl core::ops::Add for Fp {
    type Output = Fp;

    #[inline]
    fn add(self, other: Fp) -> Fp {
        let (sum, over) = self.0.overflowing_add(other.0);
        // a + b lies in [0, 2P). On overflow past 2^64 the field result is
        // sum + (2^64 - P) = sum + EPSILON, already canonical. Otherwise one
        // conditional subtraction canonicalizes.
        let mut r = sum;
        if over {
            r = r.wrapping_add(EPSILON);
        } else if r >= P {
            r -= P;
        }
        Fp(r)
    }
}

impl core::ops::Sub for Fp {
    type Output = Fp;

    #[inline]
    fn sub(self, other: Fp) -> Fp {
        let (diff, borrow) = self.0.overflowing_sub(other.0);
        // On borrow the wrapped value is a - b + 2^64; the field result a - b + P
        // is that minus (2^64 - P) = minus EPSILON.
        let r = if borrow { diff.wrapping_sub(EPSILON) } else { diff };
        Fp(r)
    }
}

impl core::ops::Neg for Fp {
    type Output = Fp;

    #[inline]
    fn neg(self) -> Fp {
        if self.0 == 0 {
            Fp(0)
        } else {
            Fp(P - self.0)
        }
    }
}

impl core::ops::Mul for Fp {
    type Output = Fp;

    #[inline]
    fn mul(self, other: Fp) -> Fp {
        let (lo, hi) = mul_wide(self.0, other.0);
        Fp(reduce_parts(lo, hi))
    }
}

/// The full product as its low and high words.
#[cfg(not(target_arch = "wasm32"))]
#[inline]
fn mul_wide(a: u64, b: u64) -> (u64, u64) {
    let product = (a as u128) * (b as u128);
    (product as u64, (product >> 64) as u64)
}

/*
 * On wasm32 a u128 product is a call into `__multi3`, and a field multiply is
 * the inner loop of every NTT, every composition row and every Poseidon round:
 * a browser multiplied three times slower than the same core natively. wasm
 * has a 64 bit multiply, and four 32 by 32 products of it make the 128 bit
 * one inline.
 */
#[cfg(target_arch = "wasm32")]
#[inline]
fn mul_wide(a: u64, b: u64) -> (u64, u64) {
    mul_wide_limbs(a, b)
}

/// The 128 bit product from four 32 bit limb products, each exact in a u64.
/// `mid` gathers the three terms that land on bits 32..96, at most 3 * 2^32.
#[inline]
#[cfg_attr(not(any(target_arch = "wasm32", test)), allow(dead_code))]
fn mul_wide_limbs(a: u64, b: u64) -> (u64, u64) {
    const M: u64 = 0xFFFF_FFFF;
    let (a0, a1, b0, b1) = (a & M, a >> 32, b & M, b >> 32);
    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p10 = a1 * b0;
    let p11 = a1 * b1;
    let mid = (p00 >> 32) + (p01 & M) + (p10 & M);
    let lo = (p00 & M) | (mid << 32);
    let hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
    (lo, hi)
}

/// Fold a 128 bit product into the field. Writing the product as
/// `lo + 2^64 * (hi_hi * 2^32 + hi_lo)` and using `2^64 = EPSILON` and
/// `2^96 = -1` in the field, the value is `lo - hi_hi + hi_lo * EPSILON`.
///
/// Both corrections are the ones the ring operations above already use: a
/// borrow past `2^64` is worth `EPSILON` too much, so it comes back off, and a
/// carry past `2^64` is worth `EPSILON` too little, so it goes back on. The
/// second correction cannot itself carry: `hi_lo * EPSILON` is at most
/// `(2^32 - 1)^2`, which is below `P`, so the sum stays under `2^64 + P`. One
/// conditional subtraction is then enough to land in `[0, P)`, which is the
/// canonical form the rest of the crate reads, hashes and compares.
#[cfg(test)]
fn reduce128(product: u128) -> u64 {
    reduce_parts(product as u64, (product >> 64) as u64)
}

#[inline]
fn reduce_parts(lo: u64, hi: u64) -> u64 {
    let hi_hi = hi >> 32;
    let hi_lo = hi & EPSILON;

    let (mut t, borrow) = lo.overflowing_sub(hi_hi);
    if borrow {
        t = t.wrapping_sub(EPSILON);
    }
    let (mut r, carry) = t.overflowing_add(hi_lo * EPSILON);
    if carry {
        r = r.wrapping_add(EPSILON);
    }
    if r >= P {
        r -= P;
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fast reduction against the definition it replaces, over the corners
    /// that exercise both corrections: the borrow path needs a low word under
    /// the high half, and the carry path needs a product near the top of the
    /// range. The division form is the specification here, so this is the test
    /// that says the refinement changed the speed and nothing else.
    #[test]
    fn the_fast_reduction_agrees_with_the_division() {
        let corners = [
            0u64,
            1,
            2,
            EPSILON,
            EPSILON + 1,
            1 << 32,
            P - 2,
            P - 1,
            P,
            P + 1,
            u64::MAX,
            u64::MAX - 1,
        ];
        for a in corners {
            for b in corners {
                let product = (a as u128) * (b as u128);
                assert_eq!(
                    reduce128(product),
                    (product % (P as u128)) as u64,
                    "reduction disagrees on {a} times {b}"
                );
            }
        }
        /*
         * A spread of pseudorandom pairs on top of the corners, drawn by a
         * multiplicative walk so the test carries no dependency and still
         * covers the middle of the range rather than its edges alone.
         */
        let (mut x, mut y) = (0x1234_5678_9abc_def0u64, 0x0fed_cba9_8765_4321u64);
        for _ in 0..20_000 {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            y = y.wrapping_mul(2_862_933_555_777_941_757).wrapping_add(3);
            let product = (x as u128) * (y as u128);
            assert_eq!(reduce128(product), (product % (P as u128)) as u64);
        }
    }

    /// The limb product is the u128 product, on every target: the corners
    /// where every limb is full or empty, and a pseudorandom spread.
    #[test]
    fn the_limb_product_is_the_wide_product() {
        let corners = [0u64, 1, 0xFFFF_FFFF, 1 << 32, EPSILON, P - 1, P, u64::MAX, u64::MAX - 1];
        let check = |a: u64, b: u64| {
            let product = (a as u128) * (b as u128);
            assert_eq!(mul_wide_limbs(a, b), (product as u64, (product >> 64) as u64), "{a} times {b}");
        };
        for a in corners {
            for b in corners {
                check(a, b);
            }
        }
        let (mut x, mut y) = (0x9e37_79b9_7f4a_7c15u64, 0x0123_4567_89ab_cdefu64);
        for _ in 0..100_000 {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            y = y.wrapping_mul(2_862_933_555_777_941_757).wrapping_add(3);
            check(x, y);
        }
    }

    /// The reduction lands canonical, which the rest of the crate assumes when
    /// it compares elements, negates them and feeds them to the hashes.
    #[test]
    fn the_reduction_is_canonical() {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..50_000 {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let product = (x as u128) * (u64::MAX as u128);
            assert!(reduce128(product) < P, "reduction left a value at or above P");
        }
    }
}
