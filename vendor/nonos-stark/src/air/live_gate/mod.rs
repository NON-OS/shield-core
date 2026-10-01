// NONOS Operating System (AGPL-3.0-or-later)

//! Whether a spent input has to be in the pool.
//!
//! A payment is always two inputs and two outputs, so a wallet holding one
//! note pays with a dummy beside it. The circuit required membership for both,
//! which meant a wallet down to one note could not pay at all until it
//! absorbed again, and that is a pattern an observer can read. This gate makes
//! the membership equality conditional on a bit, and makes the bit cost value:
//! a dead input must be worth zero.

mod air;
mod spec;
mod trace;

pub use air::{LiveGate, LANES};
