// A test asserts by panicking, so the lints that forbid it are off here.
#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use super::{
    find_deposits, recover_deposits, DepositCandidates, DepositSearch, PoolLeaves, DEPOSIT_GAP,
};
use crate::custody::Seed;
use crate::discovery::deposit_values::deposit_values;
use crate::keys::{Account, DepositSite};
use crate::net::asset_v2::{PROD_ETH, PROD_NOX};
use crate::notes::commitment;
use crate::prover::pool_hasher;
use crate::wallet::prepare_deposit_at;
use std::collections::BTreeMap;

const SITE: DepositSite = DepositSite { chain_id: 11_155_111, pool: [0xae; 20] };
const CENT: u128 = 10_000_000_000_000_000;

fn account() -> Account {
    Account::at(&Seed::new([5u8; 64]), 0).expect("an account")
}

/// The pool's leaves: `ours` deposits of `account` at the given indices, between other leaves.
fn pool(account: &Account, ours: &[(u32, u128, u16)]) -> BTreeMap<u64, [u8; 32]> {
    let mut leaves = BTreeMap::new();
    let mut at = 0u64;
    for (k, (index, amount, fee)) in ours.iter().enumerate() {
        leaves.insert(at, [k as u8; 32]);
        at += 1;
        let blinding = account.deposit_key().blinding(&SITE, *index).expect("a blinding");
        let to = account.address();
        let request = prepare_deposit_at(&to, blinding, *amount, 0, *fee, 1).expect("a deposit");
        leaves.insert(at, request.commitment);
        at += 1;
    }
    leaves
}

#[test]
fn a_deposit_is_found_from_the_seed_alone() {
    let me = account();
    let leaves = pool(&me, &[(0, CENT, 50), (3, 20 * CENT, 50), (4, 5 * CENT, 0)]);
    let found = recover_deposits(&me, &SITE, &[PROD_ETH, PROD_NOX], &leaves);
    let indices: Vec<u32> = found.iter().map(|(i, _)| *i).collect();
    assert_eq!(indices, vec![0, 3, 4]);
    let (_, first) = &found[0];
    assert_eq!(
        (first.leaf_index, first.plain.value),
        (1, 10_000_000_000_000_000 - 50_000_000_000_000)
    );
    let cm = commitment(&pool_hasher(), &first.plain.note()).map(|e| e.value());
    assert_eq!(cm, first.cm, "the record recomputes to its leaf");
}

#[test]
fn the_search_stops_after_the_gap() {
    let me = account();
    let edge = DEPOSIT_GAP - 1;
    let inside = pool(&me, &[(edge, CENT, 50)]);
    let found = recover_deposits(&me, &SITE, &[PROD_ETH], &inside);
    assert_eq!(found.len(), 1, "the last index inside the window is found");
    let past = pool(&me, &[(DEPOSIT_GAP, CENT, 50)]);
    assert!(recover_deposits(&me, &SITE, &[PROD_ETH], &past).is_empty(), "one past it is not");
    let chained = pool(&me, &[(edge, CENT, 50), (edge + DEPOSIT_GAP, CENT, 50)]);
    let found = recover_deposits(&me, &SITE, &[PROD_ETH], &chained);
    assert_eq!(found.len(), 2, "each find moves the window on");
}

/// Candidates kept from one search serve the next unchanged: the same deposits, nothing hashed
/// again, and a deposit landing inside the hashed window found by lookup alone.
#[test]
fn kept_candidates_answer_the_next_search_without_hashing() {
    let me = account();
    let edge = DEPOSIT_GAP - 1;
    let chained = pool(&me, &[(edge, CENT, 50), (edge + DEPOSIT_GAP, CENT, 50)]);
    let search = DepositSearch::of(&me, &SITE, &[PROD_ETH]);
    let mut kept = DepositCandidates::default();
    let first = find_deposits(&search, &mut kept, &PoolLeaves::new(&chained));
    assert_eq!((first.len(), kept.indices()), (2, 3 * DEPOSIT_GAP));
    let second = find_deposits(&search, &mut kept, &PoolLeaves::new(&chained));
    assert_eq!((second.len(), kept.indices()), (2, 3 * DEPOSIT_GAP), "nothing hashed again");
    let fewer = pool(&me, &[(3, CENT, 50)]);
    let third = find_deposits(&search, &mut kept, &PoolLeaves::new(&fewer));
    assert_eq!(third.iter().map(|(i, _)| *i).collect::<Vec<_>>(), vec![3]);
    assert_eq!(kept.indices(), 3 * DEPOSIT_GAP, "a window inside what is hashed hashes nothing");
}

/// One commitment at two leaves, as two devices on the same words make with one amount at one
/// index, is two deposits.
#[test]
fn one_commitment_at_two_leaves_is_found_twice() {
    let me = account();
    let mut leaves = pool(&me, &[(0, CENT, 50)]);
    let twin = leaves[&1];
    leaves.insert(7, twin);
    let found = recover_deposits(&me, &SITE, &[PROD_ETH], &leaves);
    let at: Vec<(u32, u64)> = found.iter().map(|(i, n)| (*i, n.leaf_index)).collect();
    assert_eq!(at, vec![(0, 1), (0, 7)]);
}

#[test]
fn another_account_pool_or_chain_finds_nothing() {
    let me = account();
    let leaves = pool(&me, &[(0, CENT, 50)]);
    let other = Account::at(&Seed::new([5u8; 64]), 1).expect("an account");
    assert!(recover_deposits(&other, &SITE, &[PROD_ETH], &leaves).is_empty());
    let moved = DepositSite { pool: [0xaf; 20], ..SITE };
    assert!(recover_deposits(&me, &moved, &[PROD_ETH], &leaves).is_empty());
    let chain = DepositSite { chain_id: 1, ..SITE };
    assert!(recover_deposits(&me, &chain, &[PROD_ETH], &leaves).is_empty());
}

#[test]
fn a_random_blinding_deposit_is_not_found_this_way() {
    let me = account();
    let request = crate::wallet::prepare_deposit(&me.address(), CENT, 0, 50, 1).expect("a deposit");
    let leaves = BTreeMap::from([(0u64, request.commitment)]);
    assert!(recover_deposits(&me, &SITE, &[PROD_ETH], &leaves).is_empty());
}

/// Every standard size at every fee tried is a value the search tries, and nothing else is.
#[test]
fn every_deposit_value_is_tried() {
    let values = deposit_values(&[PROD_ETH, PROD_NOX]);
    for asset in [PROD_ETH, PROD_NOX] {
        for size in crate::wallet::deposit_split::sizes(&asset) {
            for fee in [0u16, 1, 25, 50, 99, 100] {
                let (_, value) = crate::wallet::split_deposit(size, fee).expect("a split");
                assert!(values.contains(&(asset.id, value)), "{size} at {fee}");
            }
        }
    }
    assert!(values.iter().all(|(id, _)| *id == PROD_ETH.id || *id == PROD_NOX.id));
}

/// The gap passes what one split review and one single review can hold unsent at once.
#[test]
fn the_gap_passes_what_reviews_can_hold() {
    let reviews = u32::try_from(crate::wallet::deposit_split::MAX_PIECES).expect("small") + 1;
    let unseen = u32::try_from(crate::wallet::session::deposit_draw::MOST_UNSEEN).expect("small");
    assert!(DEPOSIT_GAP > 2 * reviews + unseen, "reserved, kept unseen, and a split in flight");
}

/// The cost of the search, printed: a first sync of an account with no deposits, which hashes
/// `DEPOSIT_GAP` indices, and a later one from kept candidates, against 10,000 leaves. Run with
/// `cargo test --release -p nox_shield_core --lib time_the_deposit_search -- --ignored --nocapture`.
#[test]
#[ignore = "a measurement, not a check"]
fn time_the_deposit_search() {
    let me = account();
    let leaves: BTreeMap<u64, [u8; 32]> = (0..10_000u64)
        .map(|i| {
            let mut leaf = [0u8; 32];
            leaf[..8].copy_from_slice(&i.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_le_bytes());
            (i, leaf)
        })
        .collect();
    let search = DepositSearch::of(&me, &SITE, &[PROD_ETH, PROD_NOX]);
    let started = std::time::Instant::now();
    let pool = PoolLeaves::new(&leaves);
    let read = started.elapsed();
    let mut kept = DepositCandidates::default();
    let started = std::time::Instant::now();
    assert!(find_deposits(&search, &mut kept, &pool).is_empty());
    let first = started.elapsed();
    let started = std::time::Instant::now();
    assert!(find_deposits(&search, &mut kept, &pool).is_empty());
    let again = started.elapsed();
    let per_index = first / DEPOSIT_GAP;
    eprintln!(
        "TIMING leaves read {read:?}; first sync {first:?} ({} indices, {per_index:?} each); \
         kept sync {again:?}",
        kept.indices()
    );
}
