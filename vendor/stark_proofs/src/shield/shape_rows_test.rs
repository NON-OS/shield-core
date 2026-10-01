// NONOS Operating System (AGPL-3.0-or-later)
//! The inner join-split's row budget: the stacked rows and the trace length
//! they round up to, so a region added to the join-split shows what it costs.

use crate::crypto::stark::air::Air;
use crate::crypto::stark::field::Fp;
use crate::shield::join::{join_split_shape, INTENT_WORDS};
use crate::shield::member::TREE_DEPTH;

#[test]
fn the_join_split_row_budget() {
    let shape = join_split_shape(TREE_DEPTH, &[Fp::ZERO; INTENT_WORDS]);
    let mut stacked = 0usize;
    for r in shape.regions() {
        let a = r.boxed();
        std::println!("  region rows {:>6} width {:>3}", a.rows(), a.trace_width());
        stacked += a.rows();
    }
    let rows = Air::rows(&shape);
    std::println!(
        "join-split: {stacked} stacked rows, trace 2^{} = {rows}, width {}, headroom {}",
        Air::log_trace_len(&shape),
        Air::trace_width(&shape),
        rows - stacked
    );
}
