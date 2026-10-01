// NONOS Operating System (AGPL-3.0-or-later)

use crate::crypto::stark::air::{wide_mul, LIMB_BITS, N_OUT};
use crate::crypto::stark::field::P;

/// The modulus at the width this file works in. Widened from the one home
/// rather than written again: a second literal here would be a second field.
const MODULUS: u128 = P as u128;

fn recompose(out: &[u64; N_OUT]) -> u128 {
    let mut v = 0u128;
    for (k, l) in out.iter().enumerate() {
        v |= (*l as u128) << (LIMB_BITS as usize * k);
    }
    v
}

/// Why the gadget exists. A clearing product runs past the field, so reducing it
/// discards information: the true amount and the true amount plus p are
/// different fills that a field equality cannot tell apart. The relation has to
/// hold over the integers, which is what the limb schedule gives.
#[test]
fn a_clearing_product_runs_past_the_field() {
    let amount = 3_000_000_000u64;
    let price = 1_000_000_000_000_000_000u64;
    let true_product = recompose(&wide_mul(amount, price).out);

    assert!(true_product > MODULUS, "the product fits the field, so there is nothing to prove");

    let other = true_product + MODULUS;
    assert_ne!(true_product, other, "distinct fills");
    assert_eq!(true_product % MODULUS, other % MODULUS, "same residue, indistinguishable in the field");
}
