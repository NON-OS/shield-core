//! Holding a review for the owner's yes. A review replaced by another frees the deposit indices it
//! reserved, so an abandoned review leaves no gap a restore would have to search across.

use super::{Pending, PendingBatch, Wallet};
use crate::error::{NetError, WalletError};

impl Wallet {
    /// Hold `pending` as the one send waiting for a yes, freeing the indices of the one it replaces.
    pub(super) fn hold(&self, pending: Pending) -> Result<(), WalletError> {
        let old = self.pending.lock().map_err(|_| NetError::Transport)?.replace(pending);
        self.release(old.and_then(|p| p.note).map(|n| n.draw))
    }

    /// Hold `batch` as the one split waiting for a yes, freeing the indices of the one it replaces.
    pub(super) fn hold_batch(&self, batch: PendingBatch) -> Result<(), WalletError> {
        let old = self.batch.lock().map_err(|_| NetError::Transport)?.replace(batch);
        self.release(old.map(|b| b.draw))
    }

    fn release(&self, draw: Option<u64>) -> Result<(), WalletError> {
        match draw {
            Some(id) => self.with_mut(|s| {
                s.release_deposits(id);
                Ok(())
            }),
            None => Ok(()),
        }
    }
}
