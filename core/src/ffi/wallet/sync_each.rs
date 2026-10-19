//! Recording what one fetched history holds for each account, own or view-only. Every account
//! reads the same history, so the network learns nothing of how many there are. An account's
//! deposits are also searched for from its deposit key, so a restore from the words finds them.

use super::deposit_site::active_site;
use crate::discovery::{note_commitments, spent_commitments, Log};
use crate::error::WalletError;
use crate::notes::{NoteRecord, NoteStatus};
use crate::store::Row;
use crate::wallet::deposit_recover::recovered_deposits;
use crate::wallet::watch::Watched;
use crate::wallet::{scan_history, scan_history_as, History, Session};

/// Record what the history holds for account `index`: received, deposited, spent.
pub(super) fn sync_account(
    s: &mut Session,
    index: u32,
    history: &History,
) -> Result<[u32; 3], WalletError> {
    let Some(slot) = s.at(index) else { return Ok([0; 3]) };
    let held = slot.state().held();
    let scan = scan_history(history, slot.account(), &slot.state().pending_deposits(), &held);
    let next = slot.state().next_deposit();
    let (indices, recovered): (Vec<u32>, Vec<NoteRecord>) =
        recovered_deposits(history, slot.account(), &active_site()?, next).into_iter().unzip();
    let mut known: Vec<[u64; 4]> = held.iter().map(|n| n.cm).collect();
    let mut fresh = |n: &NoteRecord| {
        let new = !known.contains(&n.cm);
        known.push(n.cm);
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
    // The highest index found is kept first, so a deposit drawn after this never reuses one.
    if let Some(last) = indices.into_iter().max() {
        s.record_to(index, Row::DepositIndex(last))?;
    }
    for note in received.into_iter().chain(deposited) {
        s.record_to(index, Row::Found(note))?;
    }
    for cm in spent {
        s.record_to(index, Row::Status { cm, status: NoteStatus::Spent })?;
    }
    s.mark_pool_at(index, &leaves(history));
    Ok(found)
}

/// Record what the history holds for one view-only account. It has no deposits of its own.
pub(super) fn sync_watched(w: &mut Watched, history: &History) -> Result<(), WalletError> {
    let held = w.state.held();
    let scan = scan_history_as(history, &w.viewer(), &[], &held);
    let known: Vec<[u64; 4]> = held.iter().map(|n| n.cm).collect();
    let rows: Vec<Row> = scan
        .received
        .into_iter()
        .filter(|n| !known.contains(&n.cm))
        .map(Row::Found)
        .chain(scan.spent.into_iter().map(|cm| Row::Status { cm, status: NoteStatus::Spent }))
        .collect();
    for row in rows {
        w.log.append(&row)?;
        w.state.apply(row);
    }
    w.state.mark_pool(&leaves(history));
    Ok(())
}

/// The active pool's leaves by position, which a held note must match to count.
fn leaves(history: &History) -> std::collections::BTreeMap<u64, [u8; 32]> {
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
