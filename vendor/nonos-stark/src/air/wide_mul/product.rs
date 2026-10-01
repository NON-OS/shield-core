// NONOS Operating System (AGPL-3.0-or-later)

//! Schoolbook multiplication over limbs. Each output weight sums the partial products that
//! land on it and the carry from the weight below, so the full product is eight 16-bit limbs
//! with an explicit carry at each weight. Keeping the carries explicit is what lets the
//! circuit constrain the multiplication limb by limb rather than trusting a single wide
//! product a field element could not hold.

use super::limbs::{split, LIMB_BITS, LIMB_MASK, N_LIMBS};

pub const N_OUT: usize = 2 * N_LIMBS;

/// The full product as eight 16 bit limbs, with the carry at each weight.
pub struct Product {
    pub out: [u64; N_OUT],
    pub carry: [u64; N_OUT],
}

/// Schoolbook over limbs. Each weight sums the partial products that land on it
/// plus the incoming carry; both stay far below the field, so the relation holds
/// over the integers rather than modulo p.
pub fn wide_mul(a: u64, b: u64) -> Product {
    let (al, bl) = (split(a), split(b));
    let mut out = [0u64; N_OUT];
    let mut carry = [0u64; N_OUT];
    let mut c = 0u64;
    for k in 0..N_OUT {
        let mut s = c;
        // Indexed on purpose: `j` runs backwards against `i` over the same
        // pair of limb arrays, which is the convolution and not a walk.
        #[allow(clippy::needless_range_loop)]
        for i in 0..N_LIMBS {
            let j = k as i64 - i as i64;
            if j >= 0 && (j as usize) < N_LIMBS {
                s += al[i] * bl[j as usize];
            }
        }
        carry[k] = c;
        out[k] = s & LIMB_MASK;
        c = s >> LIMB_BITS;
    }
    Product { out, carry }
}
