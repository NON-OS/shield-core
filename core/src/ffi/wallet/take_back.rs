//! Taking back notes whose spend was never settled, against the pool's
//! whole history read over Tor just now. The rule is `wallet::take_back`.

use super::Wallet;
use crate::error::WalletError;
use crate::net::pool::RPCS;
use crate::notes::NoteStatus;
use crate::store::Row;
use crate::wallet::take_back::releasable;
use crate::wallet::{fetch_history, scan_history};

#[uniffi::export]
impl Wallet {
    /// Read the pool, record what it shows spent, and return to the balance
    /// every note held in flight whose spend the chain never settled. Returns
    /// how many came back.
    pub fn take_back_pending(&self) -> Result<u32, WalletError> {
        self.with(|_| ())?;
        let tor = self.tor()?;
        let history = fetch_history(&tor, &RPCS)?;
        self.with_mut(|s| {
            let (pending, spent) = {
                let held = s.state().held();
                let scan =
                    scan_history(&history, s.account(), &s.state().pending_deposits(), &held);
                let pending: Vec<[u64; 4]> =
                    held.iter().filter(|n| n.status == NoteStatus::Pending).map(|n| n.cm).collect();
                (pending, scan.spent)
            };
            for cm in &spent {
                s.record(Row::Status { cm: *cm, status: NoteStatus::Spent })?;
            }
            let back = releasable(&pending, &spent);
            for cm in &back {
                s.record(Row::Status { cm: *cm, status: NoteStatus::Unspent })?;
            }
            Ok(u32::try_from(back.len()).unwrap_or(u32::MAX))
        })
    }
}
