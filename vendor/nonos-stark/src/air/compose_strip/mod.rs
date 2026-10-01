// NONOS Operating System (AGPL-3.0-or-later)

//! The compose strip: the inner transition's recompute as rows of witnessed
//! products under periodic schedules, replacing one constraint of the
//! inner's degree with many of degree four. `plan` holds the shape, `trace`
//! places the witness, `air` checks it; the plan is emitted by host tooling
//! from a recording of the inner's own code.

mod air;
mod plan;
mod trace;

pub use air::ComposeStrip;
pub use plan::{OpSched, OutStatement, RowSched, StripPlan, EMPTY};
