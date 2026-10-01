// NONOS Operating System (AGPL-3.0-or-later)

//! A straight-line program as a region: six columns, one step per row.

mod air;
mod program;

pub use air::{LineEval, N_PERIODIC as LINE_PERIODIC};
pub use program::{LineOp, Program};
