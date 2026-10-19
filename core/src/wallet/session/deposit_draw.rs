//! Drawing deposit indices for the active account, and keeping a deposit under the one it drew.
//! A draw and its reservation happen under the one session lock, so two reviews alive at once never
//! hold one index. A review's index is written only when the owner says yes, and the yes is refused
//! when a deposit kept or found since the review has taken that index.
//!
//! An index kept for a deposit that never lands, a ticket left unpaid or a send that failed, leaves
//! an empty index a restore must search across. Once `MOST_UNSEEN` such indices are kept, a draw
//! takes one of them again instead of a new one, so the empty run stays short of `DEPOSIT_GAP`.

use super::Session;
use crate::error::WalletError;
use crate::keys::DepositSite;
use crate::notes::NotePlaintext;
use crate::store::Row;
use std::time::{Duration, Instant};

/// How long a drawn index stays reserved for its review. Longer than a review lives, with room
/// for the reads between the draw and the review, after which the index can be drawn again.
pub(crate) const RESERVED_FOR: Duration = Duration::from_secs(300);

/// Indices kept and not yet seen in the pool past which a draw takes one of them again. If both
/// deposits at such an index land, each is found, and the two show the same owner digest on chain.
pub(crate) const MOST_UNSEEN: usize = 8;

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
    /// `n` indices of the active account, each with its blinding at `site`, reserved until `now`
    /// plus `RESERVED_FOR`: the lowest neither used nor reserved, or once `MOST_UNSEEN` kept indices
    /// are not seen in the pool, those first.
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
        let unseen = unseen(slot, site)?;
        if unseen.len() >= MOST_UNSEEN {
            let free = unseen.into_iter().filter(|(i, _)| !slot.reserved.contains_key(i));
            drawn.extend(free.take(n));
        }
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

/// The indices `slot` kept whose deposit the pool has not been seen to store, lowest first, each
/// with its blinding. A deposit is seen once a note with its blinding is held.
fn unseen(
    slot: &super::slot::Slot,
    site: &DepositSite,
) -> Result<Vec<(u32, [u64; 4])>, WalletError> {
    let seen: std::collections::BTreeSet<[u64; 4]> =
        slot.state.held().iter().map(|n| n.plain.blinding).collect();
    let mut out = Vec::new();
    for index in slot.state.used_deposits() {
        let blinding = slot.account.deposit_key().blinding(site, index)?;
        if !seen.contains(&blinding) {
            out.push((index, blinding));
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "deposit_draw_test.rs"]
mod deposit_draw_test;
