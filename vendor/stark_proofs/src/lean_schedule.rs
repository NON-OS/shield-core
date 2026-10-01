// NONOS Operating System (AGPL-3.0-or-later)
//! The membership selector schedule, transcribed term for term from
//! `Shield.Checkpoint` (`lean/Shield/Checkpoint.lean`).
//!
//! The Lean proves the checkpoint rule over this schedule. A circuit is tied to
//! those proofs only by a test that reads its periodic columns and compares every
//! live row with these functions, as `checkpoint_lean_test` does for the pool.
//! One copy, so the pool's tie and any other circuit's tie read the same
//! transcription and cannot drift from each other.

/// `Shield.Checkpoint.atRowBoundary`.
pub fn at_row_boundary(l: usize, within: usize) -> bool {
    within % l == l - 1
}

/// `Shield.Checkpoint.opSel`.
pub fn op_sel(span: usize, count: usize, opening: usize, within: usize) -> bool {
    within == span - 1 && opening + 1 < count
}

/// `Shield.Checkpoint.slotCol`: `slotFixed` off the opening boundary.
pub fn slot_col(
    l: usize,
    depth: usize,
    span: usize,
    count: usize,
    opening: usize,
    within: usize,
) -> bool {
    at_row_boundary(l, within) && within + l < depth * l && !op_sel(span, count, opening, within)
}

/// `Shield.Checkpoint.cpCol`: `cpSel` off the opening boundary.
pub fn cp_col(
    l: usize,
    depth: usize,
    span: usize,
    count: usize,
    opening: usize,
    within: usize,
) -> bool {
    at_row_boundary(l, within) && within + 1 == depth * l && !op_sel(span, count, opening, within)
}
