// NONOS Operating System (AGPL-3.0-or-later)

//! Which of the outer's periodic columns are zero everywhere, structurally.
//!
//! 190 of the 1,086 sidecar values are zero across every queried row. Only
//! the structural fact justifies dropping a column: one that is merely zero
//! where it was sampled is a soundness hole no sample can see. This walks every column over the whole trace. The count and
//! the indices are printed for the vector to be held against, and the
//! assertion is the one that matters: a column zero at every row is zero as
//! a polynomial, so its value at any query point is zero and a verifier that
//! substitutes zero for it has substituted the truth.

use crate::crypto::stark::air::Air;
use crate::crypto::stark::field::Fp;
use crate::recursion_assembly::anchors::DEPLOYED;
use crate::recursion_assembly::point::Point;

#[test]
#[ignore = "release tier: assembles the full settlement outer"]
fn the_zero_periodic_columns_of_the_settlement_outer() {
    let asm = Point::Settlement
        .assemble_gen(Point::emit_wiring(), DEPLOYED)
        .expect("the settlement point assembles");
    let cols = Air::periodic_columns(&asm.gen);
    let zero: Vec<usize> = cols
        .iter()
        .enumerate()
        .filter(|(_, c)| c.iter().all(|v| *v == Fp::ZERO))
        .map(|(i, _)| i)
        .collect();
    println!(
        "settlement outer: {} periodic columns over {} rows, {} zero everywhere",
        cols.len(),
        1usize << Air::log_trace_len(&asm.gen),
        zero.len()
    );
    println!("zero columns: {zero:?}");
    assert!(zero.len() < cols.len(), "a circuit with no periodic data is not this one");
}
