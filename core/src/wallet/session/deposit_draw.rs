//! Drawing deposit indices for the active account, and keeping a deposit under the one it drew.
//! A draw and its reservation happen under the one session lock, so two reviews alive at once never
//! hold one index. A review's index is written only when the owner says yes, and the yes is refused
//! when a deposit kept or found since the review has taken that index.

use super::Session;
use crate::error::WalletError;
use crate::keys::DepositSite;
use crate::notes::NotePlaintext;
use crate::store::Row;
use std::time::{Duration, Instant};

/// How long a drawn index stays reserved for its review. Longer than a review lives, with room
/// for the reads between the draw and the review, after which the index can be drawn again.
pub(crate) const RESERVED_FOR: Duration = Duration::from_secs(300);

/// Indices drawn for one review, each with its blinding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Draw {
    pub(crate) drawn: Vec<(u32, [u64; 4])>,
    /// The store's mark when drawn, against which the yes checks each index.
    pub(crate) stamp: u64,
    /// This draw's reservation, so releasing it never frees another review's index.
    pub(crate) id: u64,
}

impl Session {
    /// `n` indices of the active account, the lowest neither used nor reserved, each with its
    /// blinding at `site`, reserved until `now` plus `RESERVED_FOR`.
    pub(crate) fn draw_deposits(
        &mut self,
        site: &DepositSite,
        n: usize,
        now: Instant,
    ) -> Result<Draw, WalletError> {
        self.draws = self.draws.saturating_add(1);
        let id = self.draws;
        let slot = self.slot_mut();
        slot.reserved.retain(|_, (until, _)| *until > now);
        let until = now.checked_add(RESERVED_FOR).ok_or(WalletError::Amount)?;
        let mut drawn = Vec::with_capacity(n);
        let mut index = 0u32;
        while drawn.len() < n {
            if !slot.state.deposit_used(index) && !slot.reserved.contains_key(&index) {
                drawn.push((index, slot.account.deposit_key().blinding(site, index)?));
            }
            index = index.checked_add(1).ok_or(WalletError::Amount)?;
        }
        for (index, _) in &drawn {
            slot.reserved.insert(*index, (until, id));
        }
        Ok(Draw { drawn, stamp: slot.state.deposit_stamp(), id })
    }

    /// Free the indices draw `id` reserved and did not keep, as when its review is replaced.
    pub(crate) fn release_deposits(&mut self, id: u64) {
        self.slot_mut().reserved.retain(|_, (_, by)| *by != id);
    }

    /// Keep a deposit of the active account drawn at `index` when the store's mark was `stamp`:
    /// its index first, then its note, both on disk before the deposit leaves. Refused when a
    /// deposit kept or found since has taken the index, as another device's may have.
    pub(crate) fn keep_deposit(
        &mut self,
        index: u32,
        note: NotePlaintext,
        stamp: u64,
    ) -> Result<(), WalletError> {
        if self.slot().state.deposit_taken_since(index, stamp) {
            return Err(WalletError::ReviewExpired);
        }
        self.record(Row::DepositIndex(index))?;
        self.record(Row::Deposit(note))?;
        self.slot_mut().reserved.remove(&index);
        Ok(())
    }
}

#[cfg(test)]
#[path = "deposit_draw_test.rs"]
mod deposit_draw_test;
