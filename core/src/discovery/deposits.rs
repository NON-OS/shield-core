//! Finding this account's deposits again from the words alone. A deposit's blinding is drawn from
//! the seed at a deposit index, so for each index the owner digest is rebuilt, each value a deposit
//! can hold is tried, and a commitment the pool stored is a deposit of this account. Nothing is
//! asked of any server: the leaves come from the scan every wallet already reads.

use super::chain_read::{by_commitment, record};
use super::deposit_values::deposit_values;
use crate::keys::{Account, DepositSite};
use crate::net::asset::Asset;
use crate::notes::{wire_digest, NotePlaintext, NoteRecord};
use crate::prover::pool_hasher;
use stark_proofs::shield::note::{quads, Note};
use std::collections::BTreeMap;

/// Indices tried past the last one found before the search stops, as BIP-44 stops after twenty
/// empty addresses. An empty run is at most the indices the reviews alive at once reserve, 21, and
/// the indices kept and not seen in the pool, which a draw holds near `MOST_UNSEEN` and a split can
/// raise by 20 until its deposits land, so 64 passes it with room.
pub const DEPOSIT_GAP: u32 = 64;

/// The deposits of `account` among `leaves`, each with the index its blinding was drawn at,
/// searching from index `from` until `DEPOSIT_GAP` indices in a row find nothing.
pub fn recover_deposits(
    account: &Account,
    site: &DepositSite,
    assets: &[Asset],
    leaves: &BTreeMap<u64, [u8; 32]>,
    from: u32,
) -> Vec<(u32, NoteRecord)> {
    let by_leaf = by_commitment(leaves);
    let values = deposit_values(assets);
    let h = pool_hasher();
    let spend_pk = account.address().spend_pk;
    let mut found = Vec::new();
    let mut end = from.saturating_add(DEPOSIT_GAP);
    let mut index = from;
    while index < end {
        let Ok(blinding) = account.deposit_key().blinding(site, index) else { break };
        let at = |value: u64, asset_id: u64| Note { value, asset_id, spend_pk, blinding };
        // `commitment`, with the owner digest computed once for every value tried at this index.
        let [key, blind, _] = quads(&at(0, 0).limbs());
        let owner = h.compress(&key, &blind);
        for (asset_id, value) in &values {
            let [_, _, public] = quads(&at(*value, *asset_id).limbs());
            let wire = wire_digest(&h.compress(&public, &owner).map(|e| e.value()));
            for leaf_index in by_leaf.get(&wire).into_iter().flatten() {
                let plain =
                    NotePlaintext { value: *value, asset_id: *asset_id, blinding, spend_pk };
                found.push((index, record(plain, *leaf_index, &wire)));
                end = index.saturating_add(1).saturating_add(DEPOSIT_GAP);
            }
        }
        let Some(next) = index.checked_add(1) else { break };
        index = next;
    }
    found
}

#[cfg(test)]
#[path = "deposits_test.rs"]
mod deposits_test;
