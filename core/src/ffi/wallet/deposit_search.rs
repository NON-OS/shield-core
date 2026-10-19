//! Searching accounts' deposits with the session lock released. What each search needs is taken in
//! one short call, the hashing runs without the lock, and each account's candidates are kept
//! between syncs, so a sync after the first hashes only past where they end. A lock forgets them.

use super::deposit_site::active_site;
use super::Wallet;
use crate::discovery::{find_deposits, DepositCandidates, DepositSearch, PoolLeaves};
use crate::error::{NetError, WalletError};
use crate::keys::Account;
use crate::net::pool::ACTIVE;
use crate::notes::NoteRecord;
use crate::wallet::Session;
use std::collections::BTreeMap;

/// The deposits found for one account, named by its spend key, so a session that changed while the
/// search ran never records them for another account.
pub(super) struct Recovered {
    pub(super) spend_pk: [u64; 4],
    pub(super) found: Vec<(u32, NoteRecord)>,
}

/// Each account's candidates, by spend key.
pub(super) type Candidates = BTreeMap<[u64; 4], DepositCandidates>;

/// The deposits recovered for the account with `spend_pk`, or none.
pub(super) fn recovered_for<'a>(
    all: &'a [Recovered],
    spend_pk: &[u64; 4],
) -> &'a [(u32, NoteRecord)] {
    all.iter().find(|r| r.spend_pk == *spend_pk).map_or(&[], |r| r.found.as_slice())
}

impl Wallet {
    /// The searches for the accounts `pick` names, taken under the lock in one short call.
    pub(super) fn searches(
        &self,
        pick: impl FnOnce(&Session) -> Vec<&Account>,
    ) -> Result<Vec<DepositSearch>, WalletError> {
        let site = active_site()?;
        self.with(|s| {
            pick(s).into_iter().map(|a| DepositSearch::of(a, &site, ACTIVE.assets)).collect()
        })
    }

    /// Run each search against `pool` with no session lock held. With `only`, the candidates of
    /// accounts not searched are forgotten, as at a sync of every account.
    pub(super) fn recover(
        &self,
        searches: &[DepositSearch],
        pool: &PoolLeaves,
        only: bool,
    ) -> Result<Vec<Recovered>, WalletError> {
        let mut kept = self.candidates.lock().map_err(|_| NetError::Transport)?;
        let mut out = Vec::with_capacity(searches.len());
        for search in searches {
            let spend_pk = search.spend_pk();
            let mut candidates = kept.remove(&spend_pk).unwrap_or_default();
            let found = find_deposits(search, &mut candidates, pool);
            kept.insert(spend_pk, candidates);
            out.push(Recovered { spend_pk, found });
        }
        if only {
            kept.retain(|pk, _| out.iter().any(|r| r.spend_pk == *pk));
        }
        Ok(out)
    }

    /// Forget every account's candidates, as the session they came from is gone.
    pub(super) fn forget_candidates(&self) {
        if let Ok(mut kept) = self.candidates.lock() {
            kept.clear();
        }
    }
}
