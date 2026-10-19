// A test asserts by panicking, so the lints that forbid it are off here.
#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! A deposit made by one wallet found again by a second restored from the same words, with
//! nothing but the pool's public logs between them.

use super::super::deposit_site::active_site;
use super::sync_account;
use crate::custody::HardwareGuard;
use crate::error::CustodyError;
use crate::keys::note_nullifier_wire;
use crate::net::rpc::RawLog;
use crate::notes::NoteStatus;
use crate::store::Row;
use crate::wallet::{prepare_deposit, prepare_deposit_at, History, Paths, Session};

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

/// Wallet 1 draws and keeps a deposit the way a review and its yes do, and returns its leaf.
fn deposit(s: &mut Session, amount: u128) -> [u8; 32] {
    let [(index, blinding)] = <[_; 1]>::try_from(
        s.draw_deposits(&active_site().expect("the pool"), 1, &[]).expect("drawn"),
    )
    .expect("one");
    let request = prepare_deposit_at(&s.address(), blinding, amount, 0, 50, 1).expect("a deposit");
    s.keep_deposit(index, request.note).expect("kept");
    request.commitment
}

#[test]
fn a_deposit_comes_back_from_the_words_alone_and_spends() {
    let (one_dir, mut one) = restored("one");
    let first = deposit(&mut one, CENT);
    let second = deposit(&mut one, 20 * CENT);
    let pool = history(&[[1; 32], first, [2; 32], second], &[]);
    sync_account(&mut one, 0, &pool).expect("synced");
    let kept: Vec<_> = one.state().spendable().iter().map(|n| (n.cm, n.leaf_index)).collect();
    assert_eq!(kept.len(), 2, "wallet 1 holds both from its store");

    let (two_dir, mut two) = restored("two");
    assert!(two.state().spendable().is_empty());
    let [_, deposited, _] = sync_account(&mut two, 0, &pool).expect("synced");
    assert_eq!(deposited, 2);
    let found: Vec<_> = two.state().spendable().iter().map(|n| (n.cm, n.leaf_index)).collect();
    assert_eq!(found, kept, "the same notes at the same leaves, so spendable as wallet 1's");
    assert_eq!(two.state().next_deposit(), 2, "the next deposit passes the ones found");
    let again = sync_account(&mut two, 0, &pool).expect("synced");
    assert_eq!(again, [0, 0, 0], "a second sync records nothing twice");
    std::fs::remove_dir_all(&one_dir).ok();
    std::fs::remove_dir_all(&two_dir).ok();
}

#[test]
fn a_spent_deposit_shows_spent_after_a_restore() {
    let (one_dir, mut one) = restored("spent-one");
    let leaf = deposit(&mut one, CENT);
    let unspent = deposit(&mut one, 2 * CENT);
    let pool = history(&[leaf, unspent], &[]);
    sync_account(&mut one, 0, &pool).expect("synced");
    let note = one.state().spendable()[0].cm;
    let nullifier = note_nullifier_wire(one.account(), &note, 0);
    let spent = history(&[leaf, unspent], &[nullifier]);

    let (two_dir, mut two) = restored("spent-two");
    let [_, deposited, marked] = sync_account(&mut two, 0, &spent).expect("synced");
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
    let [_, deposited, _] = sync_account(&mut s, 0, &pool).expect("synced");
    assert_eq!(deposited, 1);
    let spendable = s.state().spendable();
    assert_eq!(spendable.len(), 1);
    assert_eq!(spendable[0].leaf_index, 1);
    assert_eq!(spendable[0].plain.blinding, request.note.blinding);
    assert_eq!(s.state().next_deposit(), 0, "an old deposit uses no index");
    std::fs::remove_dir_all(&dir).ok();
}
