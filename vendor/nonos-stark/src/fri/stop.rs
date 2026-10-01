// NONOS Operating System (AGPL-3.0-or-later)

//! Stopping the fold early, and what the final layer is when it stops.
//!
//! Folding all the way to a constant costs a layer per halving, and every
//! layer costs every query a pair and a Merkle path. The last `FRI_STOP_LOG`
//! halvings are replaced by sending the final polynomial itself: its
//! `2^FRI_STOP_LOG` coefficients, once, in the head. A verifier evaluates
//! it at each query's final point by Horner and compares that to the last
//! fold, which is the same degree claim FRI carried, checked by evaluation
//! rather than by folding. A polynomial sent as coefficients has degree
//! under `2^k` by construction, so nothing is weakened; the constancy check
//! was exactly this check for `k = 0`.
//!
//! The coefficients are read off a sub-coset of the last layer: `2^k`
//! evaluations at the points of the order `2^k` subgroup's coset determine
//! a polynomial of that degree, and the queries' evaluations elsewhere on
//! the layer are what hold a dishonest layer to it.

use super::super::field::{Fp, Fp2};
use super::super::poly::intt;
use alloc::vec::Vec;

/// Halvings replaced by the final polynomial: 256 coefficients.
pub const FRI_STOP_LOG: u32 = 8;

/// Halvings a layer performs: a fold of `2^FRI_FOLD_LOG`. A query pays one
/// Merkle path per layer whatever the factor, so folding four at a time
/// halves the layers and halves the paths, which are most of a query's
/// bytes. Four values sit under one leaf, so the factor costs a query three
/// extra field elements a layer against a whole path saved.
///
/// `radix8` folds eight at a time, for v2: three layers where radix 4 takes
/// four, each a curve of degree 7 in its challenge, which the commit grind
/// covers (docs/12 Section 1). A different build, proofs and parameter
/// identity, as `digest32` is.
#[cfg(not(feature = "radix8"))]
pub const FRI_FOLD_LOG: u32 = 2;
#[cfg(feature = "radix8")]
pub const FRI_FOLD_LOG: u32 = 3;

/// Values a fold reads together, and a FRI leaf holds.
pub const FOLD: usize = 1 << FRI_FOLD_LOG;

/// The halvings a domain of `log_n` at `log_blowup` actually skips: the
/// constant, unless the domain has fewer halvings to give, which a small
/// test domain does and a deployed one never does. At least one fold
/// always remains: with none, no query checks anything and a verifier
/// accepts any final polynomial.
pub fn stop_log(log_n: u32, log_blowup: u32) -> u32 {
    FRI_STOP_LOG.min((log_n - log_blowup).saturating_sub(1))
}

/// How many folds a domain of `log_n` at `log_blowup` performs before the
/// final polynomial is sent. This is the halving count and the radix-two
/// layer count at once, which is what the Poseidon path and the recursion
/// that verifies it in arithmetic both read.
pub fn n_folds(log_n: u32, log_blowup: u32) -> usize {
    (log_n - log_blowup - stop_log(log_n, log_blowup)) as usize
}

/// Layers at the fold factor: each takes `FRI_FOLD_LOG` halvings, and what
/// the layers do not take is left to the final polynomial, which is cheaper
/// than a ragged last layer and costs the head alone rather than every
/// query.
///
/// A domain with fewer halvings than the stop wants still folds once. The
/// division alone gave zero layers there, and zero layers is a verifier
/// that folds nothing and accepts any final polynomial: the same hole the
/// radix-two clamp exists to close, arriving by a different route.
pub fn n_layers(log_n: u32, log_blowup: u32) -> usize {
    let halvings = log_n - log_blowup;
    let fold = FRI_FOLD_LOG as usize;
    if (halvings as usize) < fold {
        return 0;
    }
    (halvings.saturating_sub(FRI_STOP_LOG) as usize / fold).max(1)
}

/// The final polynomial's size, in halvings, at the fold factor: what the
/// layers did not take. `FRI_STOP_LOG` on a deployed domain, less on a
/// domain too small to give it.
pub fn final_log(log_n: u32, log_blowup: u32) -> u32 {
    log_n - log_blowup - (n_layers(log_n, log_blowup) as u32) * FRI_FOLD_LOG
}

/// The final polynomial's `2^k` coefficients from the last layer's
/// evaluations over the coset `shift_f * <omega_f>`, where `shift_f` and
/// `omega_f` are the domain's shift and generator raised to `2^n_folds`.
pub fn final_coefficients(layer: &[Fp2], shift_f: Fp, omega_f: Fp, k: u32) -> Vec<Fp2> {
    let n_final = layer.len();
    let m = 1usize << k;
    debug_assert!(n_final >= m && n_final.is_multiple_of(m), "the final layer is not a multiple of 2^k");
    let stride = n_final / m;
    let omega_sub = omega_f.pow(stride as u64);
    let sub0: Vec<Fp> = (0..m).map(|j| layer[j * stride].c0).collect();
    let sub1: Vec<Fp> = (0..m).map(|j| layer[j * stride].c1).collect();
    let g0 = intt(&sub0, omega_sub);
    let g1 = intt(&sub1, omega_sub);
    // f(shift_f * y) = g(y), so f's coefficient i is g's over shift_f^i.
    let inv_shift = shift_f.inv();
    let mut scale = Fp::ONE;
    let mut coeffs = Vec::with_capacity(m);
    for i in 0..m {
        coeffs.push(Fp2::new(g0[i] * scale, g1[i] * scale));
        scale = scale * inv_shift;
    }
    coeffs
}

/// The final polynomial at `x`.
pub fn horner(coeffs: &[Fp2], x: Fp2) -> Fp2 {
    let mut acc = Fp2::ZERO;
    for c in coeffs.iter().rev() {
        acc = acc * x + *c;
    }
    acc
}

/// The final point of query index `i` (its index in the first layer) on a
/// domain `shift * <omega>` after `n_folds` folds: the first-layer point
/// squared that many times.
pub fn final_point(shift: Fp, omega: Fp, i: usize, n_folds: usize) -> Fp2 {
    Fp2::from_base((shift * omega.pow(i as u64)).pow(1u64 << n_folds))
}
