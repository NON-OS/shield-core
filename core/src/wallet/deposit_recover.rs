//! An account's deposits found again in a fetched history, from its deposit key alone. Local, so it
//! runs under the session lock, over the leaves the scan already read.

use super::scan_history::view;
use super::sync_chain::History;
use crate::discovery::{note_commitments, recover_deposits};
use crate::keys::{Account, DepositSite};
use crate::net::pool::ACTIVE;
use crate::notes::NoteRecord;

/// The deposits of `account` at `site` in `h`, at index `from` or later, each with its index.
pub(crate) fn recovered_deposits(
    h: &History,
    account: &Account,
    site: &DepositSite,
    from: u32,
) -> Vec<(u32, NoteRecord)> {
    let leaves = note_commitments(&view(&h.committed));
    recover_deposits(account, site, ACTIVE.assets, &leaves, from)
}
