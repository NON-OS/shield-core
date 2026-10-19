//! Finding this account's deposits again from the words alone. A deposit's blinding is drawn from
//! the seed at a deposit index, so for each index the owner digest is rebuilt, each value a deposit
//! can hold is tried, and a commitment the pool stored is a deposit of this account. Nothing is
//! asked of any server: the leaves come from the scan every wallet already reads.
//!
//! The hashing is the cost: one owner digest and one commitment per value at each index. So the
//! candidates of an account are kept between syncs as a short prefix of each commitment, a sync
//! extends them only past where they end, and each sync is then lookups against the leaves. A
//! prefix hit is checked against the whole commitment before it counts.

use super::chain_read::{by_commitment, record};
use super::deposit_values::deposit_values;
use crate::keys::deposit_key::DepositKey;
use crate::keys::{Account, DepositSite};
use crate::net::asset::Asset;
use crate::notes::{wire_digest, NotePlaintext, NoteRecord};
use crate::prover::pool_hasher;
use nonos_stark::air::Poseidon;
use nonos_stark::field::Fp;
use stark_proofs::shield::note::{quads, Note};
use std::collections::{BTreeMap, HashSet};

/// Indices tried past the last one found before the search stops, as BIP-44 stops after twenty
/// empty addresses. An empty run is at most the indices the reviews alive at once reserve, 21, and
/// the indices kept and not seen in the pool, which a draw holds near `MOST_UNSEEN` and a split can
/// raise by 20 until its deposits land, so 64 passes it with room.
pub const DEPOSIT_GAP: u32 = 64;

/// What searching one account needs, taken from the session so the hashing can run without it.
/// The deposit key it carries wipes on drop.
pub struct DepositSearch {
    key: DepositKey,
    spend_pk: [u64; 4],
    site: DepositSite,
    values: Vec<(u64, u64)>,
    h: Poseidon,
}

impl DepositSearch {
    /// The search for `account`'s deposits of `assets` at `site`.
    pub fn of(account: &Account, site: &DepositSite, assets: &[Asset]) -> DepositSearch {
        DepositSearch {
            key: account.deposit_key().clone(),
            spend_pk: account.address().spend_pk,
            site: *site,
            values: deposit_values(assets),
            h: pool_hasher(),
        }
    }

    /// The spend key of the account searched, which names its candidates.
    pub fn spend_pk(&self) -> [u64; 4] {
        self.spend_pk
    }

    /// The owner digest and blinding of deposit `index`, or None past the derivation's range.
    fn owner(&self, index: u32) -> Option<([u64; 4], [Fp; 4])> {
        let blinding = self.key.blinding(&self.site, index).ok()?;
        let spend_pk = self.spend_pk;
        let [key, blind, _] = quads(&Note { value: 0, asset_id: 0, spend_pk, blinding }.limbs());
        Some((blinding, self.h.compress(&key, &blind)))
    }

    /// The commitment of the deposit of `value` of `asset_id` with this owner.
    fn wire(&self, owner: &[Fp; 4], blinding: [u64; 4], asset_id: u64, value: u64) -> [u8; 32] {
        let note = Note { value, asset_id, spend_pk: self.spend_pk, blinding };
        let [_, _, public] = quads(&note.limbs());
        wire_digest(&self.h.compress(&public, owner).map(|e| e.value()))
    }
}

/// One account's candidate commitments for indices 0 up to `indices`, each as its first four
/// bytes, in index order and within an index in the order of the search's values.
#[derive(Default)]
pub struct DepositCandidates {
    prefixes: Vec<u32>,
    indices: u32,
}

impl DepositCandidates {
    /// Indices covered so far.
    pub fn indices(&self) -> u32 {
        self.indices
    }

    /// Hash the candidates of every index from where they end up to `to`.
    fn extend(&mut self, search: &DepositSearch, to: u32) {
        while self.indices < to {
            let Some((blinding, owner)) = search.owner(self.indices) else { return };
            for (asset_id, value) in &search.values {
                self.prefixes.push(prefix(&search.wire(&owner, blinding, *asset_id, *value)));
            }
            self.indices = self.indices.saturating_add(1);
        }
    }
}

/// The pool's leaves, read once per sync for every account searched.
pub struct PoolLeaves {
    by_cm: BTreeMap<[u8; 32], Vec<u64>>,
    prefixes: HashSet<u32>,
}

impl PoolLeaves {
    pub fn new(leaves: &BTreeMap<u64, [u8; 32]>) -> PoolLeaves {
        let by_cm = by_commitment(leaves);
        let prefixes = by_cm.keys().map(prefix).collect();
        PoolLeaves { by_cm, prefixes }
    }
}

fn prefix(wire: &[u8; 32]) -> u32 {
    let [a, b, c, d, ..] = *wire;
    u32::from_be_bytes([a, b, c, d])
}

/// The deposits of the account `search` names among `pool`, each with the index its blinding was
/// drawn at, searching from index 0 until `DEPOSIT_GAP` indices in a row find nothing. Every
/// leaf holding a found commitment is a deposit of its own. `candidates` grows as far as the search
/// reaches and is kept for the next sync.
pub fn find_deposits(
    search: &DepositSearch,
    candidates: &mut DepositCandidates,
    pool: &PoolLeaves,
) -> Vec<(u32, NoteRecord)> {
    let per = search.values.len().max(1);
    let mut reach = DEPOSIT_GAP;
    loop {
        candidates.extend(search, reach);
        let hits: Vec<(u32, usize)> = candidates
            .prefixes
            .iter()
            .enumerate()
            .filter(|(_, p)| pool.prefixes.contains(p))
            .filter_map(|(at, _)| {
                Some((u32::try_from(at.checked_div(per)?).ok()?, at.checked_rem(per)?))
            })
            .collect();
        let found = confirmed(search, pool, &hits);
        let mut next = DEPOSIT_GAP;
        for (index, _) in &found {
            if *index < next {
                next = next.max(index.saturating_add(1).saturating_add(DEPOSIT_GAP));
            }
        }
        // Past the end of what can be derived, or the window closed inside what is hashed.
        if next <= candidates.indices || candidates.indices < reach {
            return found.into_iter().filter(|(i, _)| *i < next).collect();
        }
        reach = next;
    }
}

/// The prefix hits whose whole commitment is a leaf, one record per leaf holding it.
fn confirmed(
    search: &DepositSearch,
    pool: &PoolLeaves,
    hits: &[(u32, usize)],
) -> Vec<(u32, NoteRecord)> {
    let mut found = Vec::new();
    for (index, at) in hits {
        let (Some((blinding, owner)), Some((asset_id, value))) =
            (search.owner(*index), search.values.get(*at))
        else {
            continue;
        };
        let wire = search.wire(&owner, blinding, *asset_id, *value);
        for leaf_index in pool.by_cm.get(&wire).into_iter().flatten() {
            let spend_pk = search.spend_pk;
            let plain = NotePlaintext { value: *value, asset_id: *asset_id, blinding, spend_pk };
            found.push((*index, record(plain, *leaf_index, &wire)));
        }
    }
    found
}

/// The deposits of `account` among `leaves`, searched from nothing, with no candidates kept.
pub fn recover_deposits(
    account: &Account,
    site: &DepositSite,
    assets: &[Asset],
    leaves: &BTreeMap<u64, [u8; 32]>,
) -> Vec<(u32, NoteRecord)> {
    let search = DepositSearch::of(account, site, assets);
    find_deposits(&search, &mut DepositCandidates::default(), &PoolLeaves::new(leaves))
}

#[cfg(test)]
#[path = "deposits_test.rs"]
mod deposits_test;
