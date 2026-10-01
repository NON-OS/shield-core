//! Following the spend published last in the whole pool history, read over Tor as every wallet
//! reads it: published again after 15 minutes, offered to its owner after 30.

use super::publish::{now, read_record};
use super::publish_view::{follow, SpendFollow};
use super::Wallet;
use crate::error::WalletError;
use crate::net::pool::{ACTIVE, RPCS};
use crate::wallet::fetch_history;
use crate::wallet::publish::{handoff_nullifiers, landed, next, Next, SELF_SETTLE_AFTER};

#[uniffi::export]
impl Wallet {
    /// One look at the spend published last. Asked at most once a minute, as a scan is.
    pub fn follow_spend(&self) -> Result<SpendFollow, WalletError> {
        self.with(|_| ())?;
        let dir = self.handoff_dir();
        let record = read_record(&dir).ok_or(WalletError::Unavailable)?;
        let pair = handoff_nullifiers(&dir)?;
        let history = fetch_history(self.tor()?.as_ref(), &RPCS)?;
        let now = now()?;
        let (step, offered) = next(now, &record, landed(&history.nullifiers, &pair));
        if step != Next::Republish {
            return Ok(follow(&record, now, step, offered));
        }
        let (again, refusal) = self.publish_from(&dir, Some(&record))?;
        Ok(SpendFollow { refusal, ..follow(&again, now, step, offered) })
    }
}

impl Wallet {
    /// Whether the owner may settle the spend proved last now: with no lander, with nothing
    /// published, or 30 minutes after the first publication.
    pub(super) fn self_settle_open(&self) -> Result<bool, WalletError> {
        let Some(record) = read_record(&self.handoff_dir()) else { return Ok(true) };
        Ok(ACTIVE.landers.is_empty() || now()? >= record.first.saturating_add(SELF_SETTLE_AFTER))
    }
}
