// NONOS Operating System (AGPL-3.0-or-later)

//! Where a consistency query's DEEP value is read: FRI's own layer-zero
//! opening, at FRI's own position.
//!
//! FRI proves that the codeword under its first root is close to low degree.
//! A consistency query proves that the DEEP combination of the trace, the
//! composition and the periodic columns equals the codeword at a random
//! position. Neither says anything about the codeword the other one used
//! unless the value is read from the commitment FRI tested, and neither is
//! ground unless the position is one FRI drew after its nonce.
//!
//! Format 4 got the first half: the DEEP value was opened under FRI's first
//! root. It drew its positions from the STARK transcript, though, before any
//! nonce, so a prover could re-roll them for one re-blinded commitment and
//! the consistency check stood on its queries alone. Format 5 runs the check
//! at FRI's positions, so the opening FRI already carries for its first fold
//! is the DEEP opening and nothing is opened twice.
//!
//! Layer zero commits `FOLD` values a leaf: leaf `i` holds positions `i`,
//! `i + q`, ..., `i + (FOLD - 1) q` of a domain of `FOLD q`, and FRI's opening
//! at position `p` is leaf `p mod q` in that order. The DEEP value at `p` is
//! its slot `p / q`.

use super::super::field::Fp2;
use super::super::fri::FRI_FOLD_LOG;
use super::types::LayerOpeningExt;

/// The leaf index and the slot of position `p` in a domain of `n`.
pub fn leaf_of(p: usize, n: usize) -> (usize, usize) {
    let q = n >> FRI_FOLD_LOG;
    (p % q, p / q)
}

/// The DEEP value at `p`, read from FRI's layer-zero opening at `p`. Only
/// meaningful once FRI has checked that opening, which the verifier has by
/// the time it asks: FRI returns a position only after its chain verified.
pub fn value(layer_zero: &LayerOpeningExt, p: usize, n: usize) -> Fp2 {
    layer_zero.v[leaf_of(p, n).1]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::Fp;
    use crate::fri_ext::{fri_prove_ext_layer_zero, fri_verify_ext_seeded};
    use alloc::vec::Vec;

    /// A word of low degree: a polynomial of degree 7 on a coset of `n`.
    fn word(n: usize) -> Vec<Fp2> {
        let shift = Fp::from_u64(7);
        let omega = crate::fri::root_of_unity(n.trailing_zeros());
        (0..n)
            .map(|k| {
                let x = shift * omega.pow(k as u64);
                let mut acc = Fp::ZERO;
                for c in (1..9u64).rev() {
                    acc = acc * x + Fp::from_u64(c);
                }
                Fp2::new(acc, acc + Fp::ONE)
            })
            .collect()
    }

    const N: usize = 1 << 12;
    const LOG_N: u32 = 12;

    #[test]
    fn the_value_at_a_position_is_the_codeword_there() {
        let c = word(N);
        let seed = [9u8; 32];
        let (fri, _, positions) = fri_prove_ext_layer_zero(&c, Fp::from_u64(7), 3, 8, 0, Some(&seed));
        for (k, &p) in positions.iter().enumerate() {
            assert_eq!(value(&fri.queries[k].layers[0], p, N), c[p], "position {p}");
        }
    }

    #[test]
    fn the_verifier_returns_the_prover_positions() {
        let c = word(N);
        let seed = [9u8; 32];
        let (fri, _, positions) = fri_prove_ext_layer_zero(&c, Fp::from_u64(7), 3, 8, 0, Some(&seed));
        let got = fri_verify_ext_seeded(&fri, Fp::from_u64(7), LOG_N, 3, 8, 0, Some(&seed));
        assert_eq!(got, Some(positions));
    }

    #[test]
    fn another_seed_refuses() {
        let c = word(N);
        let (fri, _, _) = fri_prove_ext_layer_zero(&c, Fp::from_u64(7), 3, 8, 0, Some(&[9u8; 32]));
        let s = Fp::from_u64(7);
        assert_eq!(fri_verify_ext_seeded(&fri, s, LOG_N, 3, 8, 0, Some(&[8u8; 32])), None);
        assert_eq!(fri_verify_ext_seeded(&fri, s, LOG_N, 3, 8, 0, None), None);
    }

    #[test]
    fn slots_follow_the_leaf_order() {
        for p in 0..64 {
            let (i, slot) = leaf_of(p, 64);
            assert_eq!(i + slot * (64 >> FRI_FOLD_LOG), p);
        }
    }
}
