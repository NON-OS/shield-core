// NONOS Operating System (AGPL-3.0-or-later)

//! A region a recursion can recompute.
//!
//! The wired engine stacks regions as trait objects, which is everything a
//! prover needs and nothing a recursive verifier can use: a boxed region
//! offers its transition over one concrete field, and the verifier one layer
//! up needs it over the tower. `WiredMultiGen` closes that by holding a typed
//! list beside the boxes. This is the bound that list satisfies, so the same
//! wrapper serves the shield's regions and the settlement outer's, and a
//! recursion over a recursion is the same construction as a recursion over a
//! payment.

use super::spec::AirExt;
use crate::field::Felt;
use alloc::boxed::Box;
use alloc::vec::Vec;

pub trait GenRegion {
    /// The region as the trait object the engine stacks. Made from the same
    /// value this list keeps, so the two views cannot disagree about what
    /// region `i` is.
    fn boxed(&self) -> Box<dyn AirExt>;

    /// The region through the trait, for layout queries before boxing.
    fn as_air(&self) -> &dyn AirExt;

    /// The region's transition over any field.
    fn transition_gen<F: Felt>(&self, window: &[F], periodic: &[F]) -> Vec<F>;
}
