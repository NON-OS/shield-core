// NONOS Operating System (AGPL-3.0-or-later)

//! The inner's mask columns: free of every constraint and every binding, and
//! filled by the hiding prover with a uniform polynomial of full FRI degree.
//! docs/12-zero-knowledge.md states what that buys.

use super::depth::MINIMAL;
use super::satisfies::satisfies;
use super::scenario::balanced_at;
use crate::crypto::stark::air::{domain_params_blown, Air};
use crate::crypto::stark::field::Fp;
use crate::recursion_assembly::inner::{hasher, hide, NQ};
use crate::shield::batch::MASK_COLUMNS;
use crate::shield::key::Break;

/// Any values in the mask columns leave an honest spend satisfied, and no
/// wiring class reaches them. A constraint or a binding that read a mask
/// column would make the mask part of the statement.
#[test]
fn the_mask_columns_are_free() {
    let mut js = balanced_at(MINIMAL, Break::None);
    let width = js.wired.trace_width();
    assert_eq!(js.wired.wired().mask_columns(), MASK_COLUMNS);
    let first = width - MASK_COLUMNS;
    assert!(
        js.wired.wired().wired_columns().iter().all(|&c| c < first),
        "a wiring class reaches a mask column"
    );
    let rows = js.witness.len() / width;
    for r in 0..rows {
        for c in first..width {
            js.witness[r * width + c] = Fp::from_u64((r * 131 + c * 7 + 1) as u64);
        }
    }
    assert!(satisfies(&js.wired, &js.witness), "a constraint reads a mask column");
}

/// `hide` writes nonzero values on the trace domain and blinds each mask
/// column up to one below the FRI bound, so its polynomial has degree
/// `bound - 1` and does not vanish on the domain.
#[test]
fn hide_fills_the_mask_to_the_fri_bound() {
    let h = hasher();
    let mut js = balanced_at(MINIMAL, Break::None);
    let width = js.wired.trace_width();
    let t = 1usize << js.wired.log_trace_len();
    let (log_n, fri_log_blowup) = domain_params_blown(&js.wired, 0);
    let bound = 1usize << (log_n - fri_log_blowup);
    let seed = [Fp::from_u64(3), Fp::from_u64(5), Fp::from_u64(7), Fp::from_u64(11)];
    let blind = hide(&h, &mut js, &seed, NQ);
    assert_eq!(blind.len(), width);
    for (c, col) in blind.iter().enumerate().skip(width - MASK_COLUMNS) {
        assert_eq!(col.len(), bound - t, "mask column {c} is not blinded to the bound");
        let zeros = (0..t).filter(|&r| js.witness[r * width + c] == Fp::ZERO).count();
        assert!(zeros < t / 64, "mask column {c} is mostly zero on the trace domain");
    }
    assert!(blind[0].len() < bound - t, "a constrained column took the mask's length");
}
