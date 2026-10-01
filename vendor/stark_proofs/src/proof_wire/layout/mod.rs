// NONOS Operating System (AGPL-3.0-or-later)

//! Where every byte of an artifact is, as arithmetic over the parameter set,
//! and one hash over that arithmetic so two implementations can prove they
//! agree instead of being read side by side.

mod geometry;
mod identity;
#[cfg(test)]
mod tests;

pub use geometry::{Layout, Section};
pub use identity::{FriLayer, Manifest, LAYOUT_DOMAIN};
