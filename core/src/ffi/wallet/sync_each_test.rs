// A test asserts by panicking, so the lints that forbid it are off here.
#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! A deposit made by one wallet found again by a second restored from the same words, with
//! nothing but the pool's public logs between them.

use super::super::deposit_search::Recovered;
use super::super::deposit_site::active_site;
use super::{leaves, sync_account};
use crate::custody::HardwareGuard;
use crate::discovery::DEPOSIT_GAP;
use crate::discovery::{find_deposits, DepositSearch, PoolLeaves};
use crate::error::CustodyError;
use crate::keys::note_nullifier_wire;
use crate::net::pool::ACTIVE;
use crate::net::rpc::RawLog;
use crate::notes::NoteStatus;
use crate::store::Row;
use crate::wallet::session::deposit_draw::MOST_UNSEEN;
use crate::wallet::{prepare_deposit, prepare_deposit_at, History, Paths, Session};
use std::time::Instant;

const CENT: u128 = 10_000_000_000_000_000;

struct Open;

impl HardwareGuard for Open {
    fn wrap(&self, key: Vec<u8>) -> Result<Vec<u8>, CustodyError> {
        Ok(key)
    }

    fn unwrap_key(&self, blob: Vec<u8>) -> Result<Vec<u8>, CustodyError> {
        Ok(blob)
    }
}

fn restored(name: &str) -> (std::path::PathBuf, Session) {
    let dir = std::env::temp_dir().join(format!("nox-recover-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).expect("a directory");
    let mut words = vec!["abandon".to_string(); 11];
    words.push("about".to_string());
    let session = Session::restore(&Paths::under(&dir), &Open, &words).expect("restored");
    (dir, session)
}

fn log(topics: Vec<[u8; 32]>) -> RawLog {
    RawLog { topics, data: Vec::new(), block: 1, tx: None }
}

fn index_topic(i: u64) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[24..].copy_from_slice(&i.to_be_bytes());
    t
}

/// A pool whose leaves are `commitments` in order, with `nullifiers` published.
fn history(commitments: &[[u8; 32]], nullifiers: &[[u8; 32]]) -> History {
    let committed = (0u64..)
        .zip(commitments)
        .map(|(i, cm)| log(vec![[0xaa; 32], *cm, index_topic(i)]))
        .collect();
    History {
        head: 1,
        committed,
        outputs: Vec::new(),
        nullifiers: nullifiers.iter().map(|n| log(vec![[0xbb; 32], *n])).collect(),
        roots: Vec::new(),
        registered: None,
    }
}

/// Account 0 synced against `h` as `sync_chain` does: its deposits searched, then recorded.
fn sync(s: &mut Session, h: &History) -> Result<[u32; 3], crate::error::WalletError> {
    let leaves = leaves(h);
    let search = DepositSearch::of(s.account(), &active_site()?, ACTIVE.assets);
    let found = find_deposits(&search, &mut Default::default(), &PoolLeaves::new(&leaves));
    let recovered = [Recovered { spend_pk: search.spend_pk(), found }];
    sync_account(s, 0, h, &leaves, &recovered)
}

/// Wallet 1 draws and keeps a deposit the way a review and its yes do, and returns its leaf.
fn deposit(s: &mut Session, amount: u128) -> [u8; 32] {
    let site = active_site().expect("the pool");
    let draw = s.draw_deposits(&site, 1, Instant::now()).expect("drawn");
    let [(index, blinding)] = <[_; 1]>::try_from(draw.drawn).expect("one");
    let request = prepare_deposit_at(&s.address(), blinding, amount, 0, 50, 1).expect("a deposit");
    s.keep_deposit(index, request.note, draw.stamp).expect("kept");
    request.commitment
}

#[test]
fn a_deposit_comes_back_from_the_words_alone_and_spends() {
    let (one_dir, mut one) = restored("one");
    let first = deposit(&mut one, CENT);
    let second = deposit(&mut one, 20 * CENT);
    let pool = history(&[[1; 32], first, [2; 32], second], &[]);
    sync(&mut one, &pool).expect("synced");
    let kept: Vec<_> = one.state().spendable().iter().map(|n| (n.cm, n.leaf_index)).collect();
    assert_eq!(kept.len(), 2, "wallet 1 holds both from its store");

    let (two_dir, mut two) = restored("two");
    assert!(two.state().spendable().is_empty());
    let [_, deposited, _] = sync(&mut two, &pool).expect("synced");
    assert_eq!(deposited, 2);
    let found: Vec<_> = two.state().spendable().iter().map(|n| (n.cm, n.leaf_index)).collect();
    assert_eq!(found, kept, "the same notes at the same leaves, so spendable as wallet 1's");
    assert_eq!(two.state().next_deposit(), 2, "the next deposit passes the ones found");
    let again = sync(&mut two, &pool).expect("synced");
    assert_eq!(again, [0, 0, 0], "a second sync records nothing twice");
    std::fs::remove_dir_all(&one_dir).ok();
    std::fs::remove_dir_all(&two_dir).ok();
}

/// Two devices on the same words each deposit 0.01 ETH at index 0, so the pool holds one commitment
/// at two leaves. Each device, and a third restored from the words, holds both notes, and spending
/// one leaves the other.
#[test]
fn one_commitment_at_two_leaves_is_two_deposits_everywhere() {
    let (a_dir, mut a) = restored("twin-a");
    let (b_dir, mut b) = restored("twin-b");
    let leaf = deposit(&mut a, CENT);
    assert_eq!(deposit(&mut b, CENT), leaf, "the same index and amount, so the same commitment");
    let pool = history(&[leaf, [4; 32], leaf], &[]);
    let (c_dir, mut c) = restored("twin-c");
    for s in [&mut a, &mut b, &mut c] {
        sync(s, &pool).expect("synced");
        let leaves: Vec<u64> = s.state().spendable().iter().map(|n| n.leaf_index).collect();
        assert_eq!(leaves, vec![0, 2], "both leaves are held");
    }
    let cm = a.state().spendable()[0].cm;
    let spent = history(&[leaf, [4; 32], leaf], &[note_nullifier_wire(a.account(), &cm, 2)]);
    sync(&mut c, &spent).expect("synced");
    let left: Vec<u64> = c.state().spendable().iter().map(|n| n.leaf_index).collect();
    assert_eq!(left, vec![0], "only the note at leaf 2 is spent");
    for dir in [a_dir, b_dir, c_dir] {
        std::fs::remove_dir_all(dir).ok();
    }
}

/// Tickets left unpaid used to fill the whole search window, twenty-four of them then, so a deposit
/// made after them was never found by a restore. Past `MOST_UNSEEN` unpaid tickets, a draw takes one
/// of their indices again, so the deposit that lands stays inside the window however many there are.
#[test]
fn a_deposit_after_many_unpaid_tickets_comes_back() {
    let (one_dir, mut one) = restored("unpaid-one");
    let landed = deposit(&mut one, 2 * CENT);
    sync(&mut one, &history(&[landed], &[])).expect("synced");
    for _ in 0..DEPOSIT_GAP + 8 {
        deposit(&mut one, CENT);
    }
    let used: Vec<u32> = one.state().used_deposits().collect();
    assert!(used.len() <= MOST_UNSEEN + 1, "unpaid tickets reuse their indices: {used:?}");
    let last = deposit(&mut one, 5 * CENT);
    let pool = history(&[landed, [6; 32], last], &[]);

    let (two_dir, mut two) = restored("unpaid-two");
    let [_, deposited, _] = sync(&mut two, &pool).expect("synced");
    assert_eq!(deposited, 2, "the deposit after the unpaid tickets is found");
    let leaves: Vec<u64> = two.state().spendable().iter().map(|n| n.leaf_index).collect();
    assert_eq!(leaves, vec![0, 2]);
    std::fs::remove_dir_all(&one_dir).ok();
    std::fs::remove_dir_all(&two_dir).ok();
}

#[test]
fn a_spent_deposit_shows_spent_after_a_restore() {
    let (one_dir, mut one) = restored("spent-one");
    let leaf = deposit(&mut one, CENT);
    let unspent = deposit(&mut one, 2 * CENT);
    let pool = history(&[leaf, unspent], &[]);
    sync(&mut one, &pool).expect("synced");
    let note = one.state().spendable()[0].cm;
    let nullifier = note_nullifier_wire(one.account(), &note, 0);
    let spent = history(&[leaf, unspent], &[nullifier]);

    let (two_dir, mut two) = restored("spent-two");
    let [_, deposited, marked] = sync(&mut two, &spent).expect("synced");
    assert_eq!((deposited, marked), (2, 1));
    let held = two.state().held();
    let status = |cm| held.iter().find(|n| n.cm == cm).map(|n| n.status);
    assert_eq!(status(note), Some(NoteStatus::Spent));
    assert_eq!(two.state().spendable().len(), 1);
    std::fs::remove_dir_all(&one_dir).ok();
    std::fs::remove_dir_all(&two_dir).ok();
}

#[test]
fn a_random_blinding_deposit_still_spends_from_its_store() {
    let (dir, mut s) = restored("old");
    let request = prepare_deposit(&s.address(), CENT, 0, 50, 1).expect("a deposit");
    s.record(Row::Deposit(request.note.clone())).expect("kept as before");
    let pool = history(&[[3; 32], request.commitment], &[]);
    let [_, deposited, _] = sync(&mut s, &pool).expect("synced");
    assert_eq!(deposited, 1);
    let spendable = s.state().spendable();
    assert_eq!(spendable.len(), 1);
    assert_eq!(spendable[0].leaf_index, 1);
    assert_eq!(spendable[0].plain.blinding, request.note.blinding);
    assert_eq!(s.state().next_deposit(), 0, "an old deposit uses no index");
    std::fs::remove_dir_all(&dir).ok();
}
