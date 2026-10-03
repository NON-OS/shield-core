// NONOS Operating System (AGPL-3.0-or-later)

//! The activity statement's count: how many of four slots are live spends,
//! and that the live ones are different spends.
//!
//! Each slot walks one nullifier to the week's spend root Λ_e. Membership
//! alone cannot see a repeat: one real spend walked four times is four honest
//! walks. So the live slots must sit at strictly increasing positions of Λ_e,
//! which makes them four different leaves, and since the pool never records a
//! nullifier twice, four different spends. Each position is recomposed from its
//! walk's direction bits elsewhere and wired in here; this region relates them.

mod air;
mod spec;
#[cfg(test)]
mod test;
mod trace;

pub use air::{ActivityCount, SLOTS};
