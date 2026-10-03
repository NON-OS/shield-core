// NONOS Operating System (AGPL-3.0-or-later)

use super::super::super::field::Felt;
use alloc::vec::Vec;

/// Slots a claim carries.
pub const SLOTS: usize = 4;
const LANES: usize = 4;

/// One row, repeated: the four live bits, the four positions, the three gaps,
/// the count, each slot's walked root and the week's root.
#[derive(Clone)]
pub struct ActivityCount {
    pub log_t: u32,
    pub live: [bool; SLOTS],
    pub pos: [u64; SLOTS],
    pub walked: [[u64; LANES]; SLOTS],
    pub root: [u64; LANES],
}

impl ActivityCount {
    pub const LIVE: usize = 0;
    pub const POS: usize = Self::LIVE + SLOTS;
    pub const GAP: usize = Self::POS + SLOTS;
    pub const K: usize = Self::GAP + SLOTS - 1;
    pub const WALKED: usize = Self::K + 1;
    pub const ROOT: usize = Self::WALKED + SLOTS * LANES;
    pub const WIDTH: usize = Self::ROOT + LANES;
    /// Transition constraints: bits, order, the first slot live, the count,
    /// gaps where the next slot is live, zero gaps where it is not, and each
    /// live slot's walk at the root.
    pub const CONSTRAINTS: usize = SLOTS + (SLOTS - 1) + 1 + 1 + 2 * (SLOTS - 1) + SLOTS * LANES;

    pub fn transition_gen<F: Felt>(&self, window: &[F], periodic: &[F]) -> Vec<F> {
        self.transition_impl(window, periodic)
    }

    pub(super) fn transition_impl<F: Felt>(&self, window: &[F], _periodic: &[F]) -> Vec<F> {
        let one = F::ONE;
        let live = |j: usize| window[Self::LIVE + j];
        let pos = |j: usize| window[Self::POS + j];
        let gap = |j: usize| window[Self::GAP + j];
        let mut out = Vec::with_capacity(Self::CONSTRAINTS);

        for j in 0..SLOTS {
            out.push(live(j) * (live(j) - one));
        }
        // Live slots first, so the count says which slots it covers.
        for j in 0..SLOTS - 1 {
            out.push(live(j + 1) * (one - live(j)));
        }
        // A claim counts at least one spend.
        out.push(live(0) - one);
        // k is the number of live slots.
        let mut sum = F::ZERO;
        for j in 0..SLOTS {
            sum = sum + live(j);
        }
        out.push(window[Self::K] - sum);

        /*
         * Where the next slot is live, its position is the last one's plus one
         * plus a gap the range region holds below 2^16. Positions are below
         * 2^16 too, recomposed from sixteen bits, so the sum cannot wrap the
         * field and the positions strictly increase. Where the next slot is
         * dead its gap is zero, so no gap cell is left to the prover.
         */
        for j in 0..SLOTS - 1 {
            out.push(live(j + 1) * (pos(j + 1) - pos(j) - one - gap(j)));
            out.push((one - live(j + 1)) * gap(j));
        }

        // A live slot's walk reaches the week's root; a dead one's goes anywhere.
        for j in 0..SLOTS {
            for l in 0..LANES {
                out.push(live(j) * (window[Self::WALKED + j * LANES + l] - window[Self::ROOT + l]));
            }
        }
        out
    }

    /// The gap a live successor leaves, zero where the successor is dead.
    /// Computed in the field, as the constraint reads it: a repeat or a fall
    /// gives a field element far above 2^16, which the range region refuses.
    pub fn gap(&self, j: usize) -> u64 {
        if self.live[j + 1] {
            let f = |v: u64| crate::field::Fp::from_u64(v);
            (f(self.pos[j + 1]) - f(self.pos[j]) - crate::field::Fp::ONE).to_u64()
        } else {
            0
        }
    }

    pub fn count(&self) -> u64 {
        self.live.iter().filter(|&&l| l).count() as u64
    }

    pub fn walked_col(slot: usize, lane: usize) -> usize {
        Self::WALKED + slot * LANES + lane
    }

    pub fn root_col(lane: usize) -> usize {
        Self::ROOT + lane
    }
}
