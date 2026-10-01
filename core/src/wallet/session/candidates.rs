//! The accounts a restore may find. Restoring derives the next accounts from the seed while it
//! is at hand and keeps them unused, since the seed is dropped before the restore returns. A
//! search then keeps those up to the last one used, and a lock forgets the rest.

use super::book::{Book, MAX_ACCOUNTS};
use super::slot::Slot;
use super::Session;
use crate::custody::Seed;
use crate::error::WalletError;
use crate::wallet::paths::Paths;

impl Session {
    pub(super) fn derive_candidates(
        &mut self,
        paths: &Paths,
        seed: &Seed,
    ) -> Result<(), WalletError> {
        self.candidates =
            (1..MAX_ACCOUNTS).map(|i| Slot::open(paths, seed, i)).collect::<Result<_, _>>()?;
        Ok(())
    }

    pub(crate) fn candidates(&self) -> &[Slot] {
        &self.candidates
    }

    /// Keep the first `found` candidates as accounts 1 to `found`, and forget the others.
    pub(crate) fn keep_candidates(
        &mut self,
        paths: &Paths,
        found: usize,
    ) -> Result<(), WalletError> {
        self.next_public = self.candidates.get(found).map(|c| c.evm().address());
        let kept: Vec<Slot> = self.candidates.drain(..).take(found).collect();
        self.more.extend(kept);
        Book { count: self.count(), active: self.active }.write(&paths.account)
    }
}
