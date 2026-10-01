// NONOS Operating System (AGPL-3.0-or-later)

//! Value conservation for a shielded transfer, as a small AIR. The region proves that the
//! signed sum of the note values on its rows is zero, so inputs equal outputs plus fee, with
//! no amount revealed. It is the arithmetic counterpart of the Lean no-inflation theorem: the
//! Lean side proves conservation survives the field once the amounts are range-bounded, and
//! this side is the circuit that enforces the sum. `air` holds the region and its transition,
//! `spec` its `Air` shape, `leg` the public input-or-output sign, `trace` the witness.

mod air;
mod spec;
mod leg;
mod range;
mod trace;

pub use air::{ValueBalance, CARRY_BITS, HI_MAX, LIMB_SHIFT};
pub use leg::Leg;
pub use range::LimbRange;
