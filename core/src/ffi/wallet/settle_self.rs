//! Settling the spend proved last from the active public account, when no lander lands it. The
//! proof pays whoever submits, so its fee comes back to this account, but the settlement names the
//! account in public and links it to the spend. It is reviewed and confirmed like a deposit.

use super::shield_view::{refused, shown};
use super::{Pending, Wallet};
use crate::error::{NetError, WalletError};
use crate::evm::shield::{review_shield, ShieldChecked, ShieldOrder};
use crate::evm::{self, Network};
use crate::ffi::evm::parse_evm_address;
use crate::ffi::PublicShield;
use crate::net::pool::ACTIVE;
use std::time::Instant;

#[uniffi::export]
impl Wallet {
    /// Work out the settlement of the spend proved last, sent from the active account on Sepolia.
    pub fn review_self_settle(&self) -> Result<PublicShield, WalletError> {
        if !self.self_settle_open()? {
            let why = "Open settlement has 30 minutes to land this without naming your account.";
            return Ok(refused(0, why));
        }
        let dir =
            self.paths().measurement.parent().map(std::path::Path::to_path_buf).unwrap_or_default();
        let calldata =
            crate::wallet::settle_self::settle_self(&dir.join("export").join("handoff"))?;
        let from = self.with(|s| s.evm().address())?;
        let order = ShieldOrder {
            pool: parse_evm_address(ACTIVE.address)?,
            token: None,
            amount: 0,
            approve_data: &[],
            deposit_data: &calldata,
            refused_as: "The pool would not settle this spend now. It may have landed already.",
        };
        let tor = self.tor()?;
        let sends = evm::nonce::recorded(&self.paths().account, Network::Sepolia, &from);
        let review = match review_shield(&tor, &from, &order, &sends)? {
            ShieldChecked::Ready(review) => review,
            ShieldChecked::Refused(why) => return Ok(refused(0, why)),
        };
        let id = self.next_review_id();
        let view = shown(id, &review, [0, 0, 0]);
        let pending = Pending {
            id,
            network: Network::Sepolia,
            from,
            tx: review.tx,
            made: Instant::now(),
            note: None,
        };
        *self.pending.lock().map_err(|_| NetError::Transport)? = Some(pending);
        Ok(view)
    }
}
