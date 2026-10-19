//! The deposit indices a held review has drawn and not yet kept, which a new review passes over,
//! so two reviews alive at once never carry one blinding.

use super::Wallet;
use crate::error::{NetError, WalletError};

impl Wallet {
    /// The index the held single deposit drew, if one is held.
    pub(super) fn held_by_single(&self) -> Result<Vec<u32>, WalletError> {
        let slot = self.pending.lock().map_err(|_| NetError::Transport)?;
        Ok(slot.as_ref().and_then(|p| p.note.as_ref()).map(|(i, _)| *i).into_iter().collect())
    }

    /// The indices the held split drew, if one is held.
    pub(super) fn held_by_split(&self) -> Result<Vec<u32>, WalletError> {
        let slot = self.batch.lock().map_err(|_| NetError::Transport)?;
        Ok(slot.iter().flat_map(|b| b.steps.iter().map(|(_, i, _)| *i)).collect())
    }
}
