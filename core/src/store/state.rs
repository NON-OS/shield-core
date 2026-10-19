//! What the rows fold up to, keyed by commitment and leaf. The balance comes only from notes held
//! here.

use super::row::Row;
use crate::notes::{NoteKey, NoteRecord};
use std::collections::BTreeMap;

/// What the wallet holds, as the rows fold up to.
#[derive(Default)]
pub struct StoreState {
    pub(super) notes: BTreeMap<NoteKey, NoteRecord>,
    cursor: u64,
    /// Deposits sent and not yet seen stored, by the commitment they will have.
    pending: BTreeMap<[u64; 4], crate::notes::NotePlaintext>,
    /// Notes held from another pool, marked at each sync and never written.
    pub(super) elsewhere: std::collections::BTreeSet<NoteKey>,
    /// The first deposit index no kept deposit has drawn.
    next_deposit: u32,
}

/// One coin's balance in its note units, split into spendable now and in flight.
#[derive(Clone, Copy, PartialEq, Eq, Debug, uniffi::Record)]
pub struct Balance {
    pub coin: crate::net::asset::Coin,
    pub spendable: u64,
    pub pending: u64,
    pub note_count: u32,
}

impl StoreState {
    pub(super) fn empty() -> StoreState {
        StoreState::default()
    }

    /// Fold one row in. A status row for an unseen note is ignored, it may await a rescan.
    pub(crate) fn apply(&mut self, row: Row) {
        match row {
            Row::Found(record) => {
                self.pending.remove(&record.cm);
                self.notes.insert(record.key(), record);
            }
            Row::Status { cm, leaf: Some(leaf), status } => {
                if let Some(record) = self.notes.get_mut(&(cm, leaf)) {
                    record.status = status;
                }
            }
            // An older store's row, written when one commitment was one note.
            Row::Status { cm, leaf: None, status } => {
                for (_, record) in self.notes.range_mut((cm, 0)..=(cm, u64::MAX)) {
                    record.status = status;
                }
            }
            Row::Cursor(at) => self.cursor = self.cursor.max(at),
            Row::Deposit(plain) => {
                let cm = crate::notes::commitment(&crate::prover::pool_hasher(), &plain.note());
                let key = [cm[0].value(), cm[1].value(), cm[2].value(), cm[3].value()];
                if self.notes.range((key, 0)..=(key, u64::MAX)).next().is_none() {
                    self.pending.insert(key, plain);
                }
            }
            Row::DepositIndex(index) => {
                self.next_deposit = self.next_deposit.max(index.saturating_add(1));
            }
        }
    }

    /// Deposits sent and not yet seen stored in the pool.
    pub fn pending_deposits(&self) -> Vec<crate::notes::NotePlaintext> {
        self.pending.values().cloned().collect()
    }

    /// Every note held, spent or not, for matching published nullifiers.
    pub fn held(&self) -> Vec<&NoteRecord> {
        self.notes.values().collect()
    }

    /// The first deposit index free to draw. It only grows, so an index is never drawn twice.
    pub fn next_deposit(&self) -> u32 {
        self.next_deposit
    }

    /// Where the next scan should start.
    pub fn cursor(&self) -> u64 {
        self.cursor
    }
}
