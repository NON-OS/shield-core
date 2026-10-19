//! Drawing deposit indices for the active account, and keeping a deposit under the one it drew.
//! The first free index is the store's, past every index a kept deposit used, so an index is never
//! drawn twice for a deposit that may leave. Indices a review holds unsent are passed over.

use super::Session;
use crate::error::{StoreError, WalletError};
use crate::keys::DepositSite;
use crate::notes::NotePlaintext;
use crate::store::Row;

impl Session {
    /// `n` indices of the active account from the first free one, passing over `held`, each with
    /// its blinding at `site`.
    pub(crate) fn draw_deposits(
        &self,
        site: &DepositSite,
        n: usize,
        held: &[u32],
    ) -> Result<Vec<(u32, [u64; 4])>, WalletError> {
        let slot = self.slot();
        let mut out = Vec::with_capacity(n);
        let mut index = slot.state.next_deposit();
        while out.len() < n {
            if !held.contains(&index) {
                out.push((index, slot.account.deposit_key().blinding(site, index)?));
            }
            index = index.checked_add(1).ok_or(WalletError::Amount)?;
        }
        Ok(out)
    }

    /// Keep a deposit of the active account: its index first, then its note, both on disk before
    /// the deposit leaves. A crash between the two wastes the index and never reuses it.
    pub(crate) fn keep_deposit(
        &mut self,
        index: u32,
        note: NotePlaintext,
    ) -> Result<(), StoreError> {
        self.record(Row::DepositIndex(index))?;
        self.record(Row::Deposit(note))
    }
}

#[cfg(test)]
#[path = "deposit_draw_test.rs"]
mod deposit_draw_test;
