// NONOS Operating System (AGPL-3.0-or-later)

//! An inner AIR whose transition a recursive verifier can recompute.

use super::super::super::field::{Felt, Fp};
use alloc::vec::Vec;

/// An inner AIR whose transition can be evaluated over any field, so a recursive
/// verifier can recompute it over the tower `Ext2<F>`. An AIR that writes its
/// transition once over `Felt` (the object-safe pattern) satisfies this by
/// forwarding to that one definition; the generic method keeps it off the
/// object-safe `AirExt`, so `ComposeCheckGen` is monomorphized on the concrete
/// inner rather than boxed.
pub trait GenericTransition {
    fn transition_gen<F: Felt>(&self, window: &[F], periodic: &[F]) -> Vec<F>;

    /// The challenge values this transition depends on, in the order
    /// `transition_gen_at` takes them. Empty for an AIR fixed by its circuit.
    fn challenges_gen(&self) -> Vec<Fp> {
        Vec::new()
    }

    /// The transition at challenges the caller supplies. The default ignores
    /// them, which is correct for an AIR that has none.
    fn transition_gen_at<F: Felt>(&self, window: &[F], periodic: &[F], chal: &[F]) -> Vec<F> {
        let _ = chal;
        self.transition_gen(window, periodic)
    }
}
