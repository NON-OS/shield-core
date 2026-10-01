// NONOS Operating System (AGPL-3.0-or-later)
//! What the pool's tree depth costs the circuit, and what it does not.
//!
//! The wrap's size is a step function in the outer's DEEP term count, and that
//! count is `2 * trace_width + outer_n_periodic + 1`. Both halves are functions
//! of the inner's shape: the outer's widest region is the composition, and the
//! composition carries the inner's frame, the claims at its periodic columns,
//! and a coefficient per inner constraint.
//!
//! So a proposal to shrink the tree has to be priced in those terms rather than
//! in rows. This pins which of the inner's numbers move with the depth.

use super::depth::DEPLOYED;
use super::scenario::balanced_at;
use crate::crypto::stark::air::Air;
use crate::shield::key::Break;

/// The inner's shape at one depth: the four numbers the outer's width is built
/// from, and the trace length, which is the one that moves.
fn shape(depth: usize) -> (usize, usize, u32, usize, usize) {
    let js = balanced_at(depth, Break::None);
    (
        js.wired.trace_width(),
        js.wired.periodic_columns().len(),
        js.wired.log_trace_len(),
        js.wired.num_transition(),
        js.wired.boundary().len(),
    )
}

/// The depth buys rows and nothing the outer's width is made of, and between 32
/// and 24 it does not even buy rows.
///
/// A membership walk is one compression per level, so a shallower tree walks
/// fewer rows. It adds no column: the sibling, the direction and the state ride
/// the same columns at every level. It adds no constraint: the transition is
/// per row, not per level. And it adds no periodic column, because the
/// production form carries siblings on the trace rather than on the schedule.
///
/// Measured, at 8, 16, 24 and 32: width 24, periodic 81, transitions 17,
/// boundaries 62, all four unmoved. `log_trace_len` is 13 at 24 and at 32 and
/// 12 at 16 and at 8, because the rows round to a power of two and the two
/// deployable depths land in the same one.
///
/// So the pool's depth is a contracts-side constant with no circuit coupling at
/// all. It is not a second route to a smaller DEEP term count, and the first
/// depth that shortens the inner is 16, whose ceiling is 65,536 notes.
#[test]
fn the_tree_depth_buys_rows_and_not_width() {
    let deep = shape(DEPLOYED);
    let shallow = shape(24);

    assert_eq!(deep.0, shallow.0, "the trace width moved with the depth");
    assert_eq!(deep.1, shallow.1, "the periodic count moved with the depth");
    assert_eq!(deep.3, shallow.3, "the transition count moved with the depth");
    assert_eq!(deep.4, shallow.4, "the boundary count moved with the depth");
    assert_eq!(
        deep.2, shallow.2,
        "24 and 32 no longer round to one trace length; the depth now buys rows \
         and the pricing above has to be redone"
    );
}

/// The numbers themselves, so a reader gets them without running a prover.
/// Printed rather than asserted past the invariant above: the widths are
/// pinned by the emitted structure file and a second copy here would be a
/// second opinion about it.
#[test]
#[ignore]
fn print_the_inner_shape_by_depth() {
    for d in [8usize, 16, 24, 32] {
        let (w, p, log_t, ntr, nb) = shape(d);
        std::println!(
            "depth {d:>2}: width {w:>3} periodic {p:>3} log_t {log_t:>2} transitions {ntr:>3} boundaries {nb:>3}"
        );
    }
}
