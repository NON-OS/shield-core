//! Recording what one fetched history holds for each account, own or view-only. Every account
//! reads the same history, so the network learns nothing of how many there are. An account's
//! deposits, searched for from its deposit key without the session lock, are recorded here too,
//! so a restore from the words finds them.

use super::deposit_search::{recovered_for, Recovered};
use crate::discovery::{note_commitments, spent_commitments, Log};
use crate::error::WalletError;
use crate::notes::{NoteKey, NoteRecord, NoteStatus};
use crate::store::Row;
use crate::wallet::watch::Watched;
use crate::wallet::{scan_history, scan_history_as, History, Session};
use std::collections::BTreeMap;

/// Record what the history holds for account `index`: received, deposited, spent. `leaves` are the
/// history's leaves by position and `recovered` the deposits searched for, read once for every
/// account.
pub(super) fn sync_account(
    s: &mut Session,
    index: u32,
    history: &History,
    leaves: &BTreeMap<u64, [u8; 32]>,
    recovered: &[Recovered],
) -> Result<[u32; 3], WalletError> {
    let Some(slot) = s.at(index) else { return Ok([0; 3]) };
    let held = slot.state().held();
    let scan = scan_history(history, slot.account(), &slot.state().pending_deposits(), &held);
    // Searched from index 0 each time: a hole below the last index used may be filled later, here
    // or by another device on the same words.
    let mine = recovered_for(recovered, &slot.account().address().spend_pk);
    let (indices, recovered): (Vec<u32>, Vec<NoteRecord>) = mine.iter().cloned().unzip();
    let mut fresh_indices: Vec<u32> =
        indices.into_iter().filter(|i| !slot.state().deposit_used(*i)).collect();
    fresh_indices.dedup();
    let mut known: Vec<NoteKey> = held.iter().map(|n| n.key()).collect();
    let mut fresh = |n: &NoteRecord| {
        let new = !known.contains(&n.key());
        known.push(n.key());
        new
    };
    let received: Vec<_> = scan.received.into_iter().filter(&mut fresh).collect();
    let deposited: Vec<_> =
        scan.deposited.into_iter().chain(recovered).filter(&mut fresh).collect();
    // A note found now may be spent already, as after a restore, so its nullifier is checked too.
    let published: Vec<[u8; 32]> =
        history.nullifiers.iter().filter_map(|l| l.topics.get(1).copied()).collect();
    let mut spent = scan.spent;
    for set in [&received, &deposited] {
        spent.extend(spent_commitments(slot.account(), set, &published));
    }
    let found = [count(received.len()), count(deposited.len()), count(spent.len())];
    // Each index found is kept first, so no deposit drawn after this reuses one, and a review that
    // drew one before this sync is refused at its yes.
    for used in fresh_indices {
        s.record_to(index, Row::DepositIndex(used))?;
    }
    for note in received.into_iter().chain(deposited) {
        s.record_to(index, Row::Found(note))?;
    }
    for key in spent {
        s.record_to(index, Row::status(key, NoteStatus::Spent))?;
    }
    s.mark_pool_at(index, leaves);
    Ok(found)
}

/// Record what the history holds for one view-only account. It has no deposits of its own.
pub(super) fn sync_watched(
    w: &mut Watched,
    history: &History,
    leaves: &BTreeMap<u64, [u8; 32]>,
) -> Result<(), WalletError> {
    let held = w.state.held();
    let scan = scan_history_as(history, &w.viewer(), &[], &held);
    let known: Vec<NoteKey> = held.iter().map(|n| n.key()).collect();
    let rows: Vec<Row> = scan
        .received
        .into_iter()
        .filter(|n| !known.contains(&n.key()))
        .map(Row::Found)
        .chain(scan.spent.into_iter().map(|key| Row::status(key, NoteStatus::Spent)))
        .collect();
    for row in rows {
        w.log.append(&row)?;
        w.state.apply(row);
    }
    w.state.mark_pool(leaves);
    Ok(())
}

/// The active pool's leaves by position, which a held note must match to count.
pub(super) fn leaves(history: &History) -> BTreeMap<u64, [u8; 32]> {
    let logs: Vec<Log> =
        history.committed.iter().map(|r| Log { topics: &r.topics, data: &r.data }).collect();
    note_commitments(&logs)
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

#[cfg(test)]
#[path = "sync_each_test.rs"]
mod sync_each_test;
