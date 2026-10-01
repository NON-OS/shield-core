//! Recording what one fetched history holds for each account, own or view-only. Every account
//! reads the same history, so the network learns nothing of how many there are.

use crate::discovery::{note_commitments, Log};
use crate::error::WalletError;
use crate::notes::NoteStatus;
use crate::store::Row;
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
    let known: Vec<[u64; 4]> = held.iter().map(|n| n.cm).collect();
    let fresh = |cm: &[u64; 4]| !known.contains(cm);
    let received: Vec<_> = scan.received.into_iter().filter(|n| fresh(&n.cm)).collect();
    let deposited: Vec<_> = scan.deposited.into_iter().filter(|n| fresh(&n.cm)).collect();
    let found = [count(received.len()), count(deposited.len()), count(scan.spent.len())];
    for note in received.into_iter().chain(deposited) {
        s.record_to(index, Row::Found(note))?;
    }
    for cm in scan.spent {
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
