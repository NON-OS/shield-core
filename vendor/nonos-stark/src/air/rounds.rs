// NONOS Operating System (AGPL-3.0-or-later)
//! An AIR whose permutation columns are built from a challenge, not from the
//! circuit.
//!
//! A grand product collapses a multiset equality into one field equation at a
//! single point. That is only an argument when the prover could not have built
//! its trace against the point, which means the point has to come after a
//! commitment to the columns the product speaks about. An AIR that implements
//! this can be proved in two rounds: its region columns are committed, the
//! challenges are drawn from that root, and only then are the permutation
//! columns filled and committed.
//!
//! `wired_challenge_tests` and `wired_forgery_tests` are why this exists. With
//! the challenges fixed in the circuit, the real settlement outer accepts a
//! witness in which two cells it says are equal are not.

use super::super::field::{Fp, Fp2};

/// The pair a group carries before the transcript draws one.
///
/// Named, and in one place, because it is not a parameter. It is the pair the
/// recorded forgery was built at: with these in force the real settlement outer
/// accepts a witness in which two cells it says are equal are not. Six group
/// constructors wrote `Fp::from_u64(5)` and `Fp::from_u64(7)` inline, which
/// made a placeholder look like a choice, and one emitted layout published them
/// as though they were the circuit's.
///
/// A group still holding these has been proved against nothing.
/// `set_challenges` replaces them; `n_challenges` reports zero until it does.
pub const UNDRAWN: (Fp, Fp) = (Fp::from_u64(5), Fp::from_u64(7));

pub trait Permuted {
    /// Where the permutation columns begin. Everything below is the regions'
    /// own witness and is committed in the first round; everything from here up
    /// is what the challenges produce and is committed in the second.
    fn region_width(&self) -> usize;

    /// Adopt the drawn challenges. Called once, between the two commitments.
    fn set_challenges(&mut self, beta: Fp, gamma: Fp);

    /// Adopt challenges drawn in `Fp2`, for an AIR whose `challenge_lanes` is
    /// two. An AIR that argues in `Fp` keeps the base components.
    fn set_challenges_ext(&mut self, beta: Fp2, gamma: Fp2) {
        self.set_challenges(beta.c0, gamma.c0)
    }

    /// Fill the permutation columns of a trace whose region columns are already
    /// final, using the challenges in force.
    fn fill_products(&self, trace: &mut [Fp]);
}
