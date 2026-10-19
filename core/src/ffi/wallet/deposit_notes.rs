use super::Wallet;
use crate::error::WalletError;
use crate::store::Balance;

impl Wallet {
    /// Per coin, what the active account holds in notes from its own deposits.
    /// They exist only in this device's storage until spent.
    pub fn deposit_notes(&self) -> Result<Vec<Balance>, WalletError> {
        self.with(|s| {
            let state = s.state();
            crate::net::pool::ACTIVE.assets.iter().map(|a| state.deposit_notes(a)).collect()
        })
    }
}
