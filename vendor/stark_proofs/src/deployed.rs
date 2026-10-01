// NONOS Operating System (AGPL-3.0-or-later)
//! The two entry points a binary needs before it ships a shape: the
//! satisfaction walk, and the deployed join-split engine.

use crate::crypto::stark::air::{Air, WiredMultiGen};
use crate::crypto::stark::field::Fp;
use crate::shield;
use crate::witness_satisfies;

/// The satisfaction walk, for binaries that gate a shape before shipping it.
pub fn witness_satisfies_public(air: &(impl Air + Sync), witness: &[Fp]) -> bool {
    witness_satisfies::satisfies(air, witness)
}

/// The deployed join-split engine alone, for binaries that derive its
/// registration constants.
pub fn shield_deployed_wired() -> WiredMultiGen {
    shield::test::scenario::balanced_deployed(shield::key::Break::None).wired
}
