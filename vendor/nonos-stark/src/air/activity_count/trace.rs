// NONOS Operating System (AGPL-3.0-or-later)

use super::super::super::field::Fp;
use super::air::{ActivityCount, SLOTS};
use alloc::vec;
use alloc::vec::Vec;

impl ActivityCount {
    /// Every row the same: the transition relates one row's own cells, so a
    /// region of any height states the same thing.
    pub fn trace(&self) -> Vec<Fp> {
        let rows = 1usize << self.log_t;
        let w = ActivityCount::WIDTH;
        let mut row = vec![Fp::ZERO; w];
        for j in 0..SLOTS {
            row[ActivityCount::LIVE + j] = if self.live[j] { Fp::ONE } else { Fp::ZERO };
            row[ActivityCount::POS + j] = Fp::from_u64(self.pos[j]);
            for l in 0..4 {
                row[ActivityCount::walked_col(j, l)] = Fp::from_u64(self.walked[j][l]);
            }
        }
        for j in 0..SLOTS - 1 {
            row[ActivityCount::GAP + j] = Fp::from_u64(self.gap(j));
        }
        row[ActivityCount::K] = Fp::from_u64(self.count());
        for l in 0..4 {
            row[ActivityCount::root_col(l)] = Fp::from_u64(self.root[l]);
        }
        let mut t = vec![Fp::ZERO; rows * w];
        for r in 0..rows {
            t[r * w..(r + 1) * w].copy_from_slice(&row);
        }
        t
    }
}
