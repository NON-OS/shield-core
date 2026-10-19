//! The held notes that came from this store's own deposits. Only a received note is
//! sealed to the wallet's key, so these are the ones a restore from the words misses.

use super::state::{Balance, StoreState};
use crate::net::asset::Asset;
use crate::notes::NoteStatus;

impl StoreState {
    /// One asset's unspent and pending value held in deposit notes.
    pub fn deposit_notes(&self, asset: &Asset) -> Balance {
        let mut b = Balance { coin: asset.coin, spendable: 0, pending: 0, note_count: 0 };
        let own = self.held_here().into_iter().filter(|n| self.deposited.contains(&n.cm));
        for n in own.filter(|n| n.plain.asset_id == asset.id) {
            match n.status {
                NoteStatus::Unspent => b.spendable = b.spendable.saturating_add(n.plain.value),
                NoteStatus::Pending => b.pending = b.pending.saturating_add(n.plain.value),
                NoteStatus::Spent => continue,
            }
            b.note_count = b.note_count.saturating_add(1);
        }
        b
    }
}
