// NONOS Operating System (AGPL-3.0-or-later)

//! The live gate and its transition. One of these per spent input decides
//! whether that input has to be in the pool.
//!
//! Membership is the walked terminal equalling the published root, and an
//! equality is a wiring class, which cannot be made conditional. So the
//! equality moves here, where it is multiplied by a bit: a live input's walk
//! must reach the published root, a dead one's walk binds nothing. The bit is
//! not free. A dead input must carry value zero, so the only thing a prover
//! buys by declaring an input dead is the right not to own a note worth
//! nothing.

use super::super::super::field::Felt;
use alloc::vec::Vec;

/// Lanes per digest, and the two roots this gate holds an input against.
pub const LANES: usize = 4;

/// One input's liveness, its value limbs, and the four digests the gate
/// compares. Every cell here is bound by the assembly to the place that
/// computes it; nothing in this region is trusted on its own.
#[derive(Clone)]
pub struct LiveGate {
    pub log_t: u32,
    /// One when the input is a real note, zero when it is a dummy.
    pub live: bool,
    /// The spent note's value limbs, low then high.
    pub value: [u64; 2],
    /// The inverse of the recomposed value, or zero when the value is zero.
    /// It is what makes liveness a function of the value rather than a choice.
    pub inv: u64,
    /// What this input's pool membership walked to, and what the pool
    /// published.
    pub walked_note: [u64; LANES],
    pub note_root: [u64; LANES],
    /// The same pair for the association set.
    pub walked_assoc: [u64; LANES],
    pub assoc_root: [u64; LANES],
    /// Lane one of the word this input's nullifier hashes beside its position:
    /// zero for a note, `dead_domain` for a dummy. The pool burns both
    /// nullifiers of every intent and cannot tell them apart, so this is what
    /// keeps a dummy's out of the space a note's occupies.
    pub dead: u64,
    /// The constant a dead input's lane must equal. Carried rather than reached
    /// for, so this region names every number it enforces.
    pub dead_domain: u64,
}

impl LiveGate {
    /// Column of the liveness bit.
    pub const LIVE: usize = 0;
    /// Columns of the value limbs, low then high.
    pub const VALUE: usize = 1;
    /// Column of the value's inverse.
    pub const INV: usize = 3;
    /// Column of the first walked note lane. The published lanes follow, then
    /// the association pair, four lanes each.
    pub const WALKED_NOTE: usize = 4;
    pub const NOTE_ROOT: usize = Self::WALKED_NOTE + LANES;
    pub const WALKED_ASSOC: usize = Self::NOTE_ROOT + LANES;
    pub const ASSOC_ROOT: usize = Self::WALKED_ASSOC + LANES;
    /// Column of the nullifier's dead lane.
    pub const DEAD: usize = Self::ASSOC_ROOT + LANES;
    pub const WIDTH: usize = Self::DEAD + 1;

    pub fn transition_gen<F: Felt>(&self, window: &[F], periodic: &[F]) -> Vec<F> {
        self.transition_impl(window, periodic)
    }

    pub(super) fn transition_impl<F: Felt>(&self, window: &[F], _periodic: &[F]) -> Vec<F> {
        let live = window[Self::LIVE];
        let one = F::ONE;
        let mut out = Vec::with_capacity(5 + 2 * LANES);

        // The bit is a bit. Without this a prover scales the gate away.
        out.push(live * (live - one));

        /*
         * The bit is the value's own, not the prover's: `live = value * inv`
         * with `inv` witnessed. A note worth nothing takes inv zero and the bit
         * follows; a note worth something cannot take the bit down without
         * failing the limb constraints below.
         *
         * It also puts the value in a constraint that does not vanish. Every
         * other rule here is multiplied by the bit or by its complement, so one
         * of them is always inert, and a cell held only by an inert rule is a
         * cell held only by the wiring. `shield_free_cells_tests` is the gate
         * that says so.
         */
        let shift = F::from_base(crate::field::Fp::from_u64(1u64 << 32));
        let value = window[Self::VALUE] + window[Self::VALUE + 1] * shift;
        out.push(live - value * window[Self::INV]);

        /*
         * A dead input carries no value. With the rule above this is an
         * equivalence rather than one direction: a nonzero value forces the bit
         * up and the two root equalities below come back, and a zero value
         * forces it down.
         */
        out.push((one - live) * window[Self::VALUE]);
        out.push((one - live) * window[Self::VALUE + 1]);

        /*
         * And the nullifier says which it was. The lane is zero for a note and
         * the dead constant for a dummy, so the two hash different words and no
         * dummy's nullifier can land on a note's without a Poseidon collision.
         * The pool needs that: it burns both nullifiers of every intent and has
         * no way to tell which input was real, so a dummy free to choose its
         * lane is a dummy free to retire somebody's note.
         */
        let dead = F::from_base(crate::field::Fp::from_u64(self.dead_domain));
        out.push(window[Self::DEAD] + live * dead - dead);

        /*
         * Membership, conditionally. A live input's walk has to reach the
         * published root lane for lane; a dead one's walk is multiplied by zero
         * and reaches wherever its siblings take it, which is what lets a
         * wallet pay from one note.
         */
        for lane in 0..LANES {
            out.push(live * (window[Self::WALKED_NOTE + lane] - window[Self::NOTE_ROOT + lane]));
            out.push(live * (window[Self::WALKED_ASSOC + lane] - window[Self::ASSOC_ROOT + lane]));
        }
        out
    }
}
