// NONOS Operating System (AGPL-3.0-or-later)

//! The gate's witness: one row holding the bit, the value limbs and the four
//! digests, repeated so every row of the region satisfies the transition.

use super::super::super::field::Fp;
use super::air::{LiveGate, LANES};
use alloc::vec;
use alloc::vec::Vec;

impl LiveGate {
    pub fn trace(&self) -> Vec<Fp> {
        let rows = 1usize << self.log_t;
        let w = LiveGate::WIDTH;
        let mut row = vec![Fp::ZERO; w];
        row[LiveGate::LIVE] = if self.live { Fp::ONE } else { Fp::ZERO };
        row[LiveGate::VALUE] = Fp::from_u64(self.value[0]);
        row[LiveGate::VALUE + 1] = Fp::from_u64(self.value[1]);
        row[LiveGate::INV] = Fp::from_u64(self.inv);
        row[LiveGate::DEAD] = Fp::from_u64(self.dead);
        for lane in 0..LANES {
            row[LiveGate::WALKED_NOTE + lane] = Fp::from_u64(self.walked_note[lane]);
            row[LiveGate::NOTE_ROOT + lane] = Fp::from_u64(self.note_root[lane]);
            row[LiveGate::WALKED_ASSOC + lane] = Fp::from_u64(self.walked_assoc[lane]);
            row[LiveGate::ASSOC_ROOT + lane] = Fp::from_u64(self.assoc_root[lane]);
        }
        /*
         * Every row carries the same values. The transition reads one row and
         * relates its own cells, so a region of any height is the same
         * statement; repeating the row is what keeps the last window honest
         * rather than pinning a boundary the assembly would have to know about.
         */
        let mut t = vec![Fp::ZERO; rows * w];
        for r in 0..rows {
            t[r * w..(r + 1) * w].copy_from_slice(&row);
        }
        t
    }

    /// The column carrying walked note lane `lane`, for the assembly's binding.
    pub fn walked_note_col(lane: usize) -> usize {
        LiveGate::WALKED_NOTE + lane
    }

    /// The column carrying published note lane `lane`.
    pub fn note_root_col(lane: usize) -> usize {
        LiveGate::NOTE_ROOT + lane
    }

    pub fn walked_assoc_col(lane: usize) -> usize {
        LiveGate::WALKED_ASSOC + lane
    }

    pub fn assoc_root_col(lane: usize) -> usize {
        LiveGate::ASSOC_ROOT + lane
    }

    /// The column carrying value limb `i`, low then high.
    pub fn value_col(i: usize) -> usize {
        LiveGate::VALUE + i
    }

    /// The column carrying the nullifier's dead lane, for the assembly's
    /// binding to the key hierarchy's fourth compression.
    pub fn dead_col() -> usize {
        LiveGate::DEAD
    }
}
