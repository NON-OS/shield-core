// NONOS Operating System (AGPL-3.0-or-later)

//! The permutation argument, the single grand product that enforces every copy binding at
//! once. `cycles` turns binding classes into a permutation, `arg` runs the challenged running
//! product whose unit boundary is the whole set of bindings, `disjoint` proves the classes do
//! not collide so one shared permutation is safe, and `layable` checks the classes an assembly
//! hands over can be laid down. The Lean `Wiring` and `GrandProduct` modules prove the two
//! properties this rests on: disjointness preserves earlier bindings, and the accumulator
//! computes the product its boundary claims.

mod arg;
mod cycles;
mod disjoint;
mod layable;

pub use cycles::{Cell, WirePermutation};
pub use arg::WiredPermutationArg;
pub use disjoint::classes_are_disjoint;
pub use layable::classes_are_layable;
