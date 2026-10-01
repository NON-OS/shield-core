// NONOS Operating System (AGPL-3.0-or-later)

//! The out-of-domain composition check for an arbitrary inner AIR.

mod constraints;
mod gadget;
mod generic;
mod slots;
mod witness;

pub use gadget::ComposeCheckGen;
pub use generic::GenericTransition;
pub use slots::Slots;
