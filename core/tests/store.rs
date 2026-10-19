/*
 * A test asserts by panicking, and a measurement prints what it read, so the
 * lints that forbid panicking and indexing are off here and nowhere else.
 */
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod keystore;

use keystore::scratch;
use nox_shield_core::custody::{generate_phrase, phrase_to_seed};
use nox_shield_core::error::StoreError;
use nox_shield_core::net::asset::{ETH, NOX};
use nox_shield_core::notes::{fresh_blinding, NotePlaintext, NoteRecord, NoteStatus};
use nox_shield_core::store::{NoteLog, Row};

fn record(value: u64, index: u64) -> NoteRecord {
    record_of(ETH.id, value, index)
}

fn record_of(asset_id: u64, value: u64, index: u64) -> NoteRecord {
    NoteRecord {
        plain: NotePlaintext {
            value,
            asset_id,
            blinding: fresh_blinding().expect("entropy"),
            spend_pk: [1, 2, 3, 4],
        },
        leaf_index: index,
        cm: [index, index + 1, index + 2, index + 3],
        status: NoteStatus::Unspent,
        found_at: index,
    }
}

#[test]
fn rows_survive_a_reopen_and_the_balance_follows_them() {
    let dir = scratch("store-reopen");
    let phrase = generate_phrase().expect("entropy");
    let seed = phrase_to_seed(&phrase).expect("seed");
    let path = dir.join("notes.log");

    let (mut log, _) = NoteLog::open(path.clone(), &seed).expect("open");
    for row in [Row::Found(record(1000, 0)), Row::Found(record(2000, 4)), Row::Cursor(8)] {
        log.append(&row).expect("append");
    }
    // A status row as a store before leaves were named wrote it, by commitment alone.
    let spent = Row::Status { cm: [0, 1, 2, 3], leaf: None, status: NoteStatus::Spent };
    log.append(&spent).expect("append");

    let (_reopened, replayed) = NoteLog::open(path, &seed).expect("reopen");
    assert_eq!(replayed.balance(&ETH).spendable, 2000, "a spent note is not spendable");
    assert_eq!(replayed.balance(&ETH).note_count, 1);
    assert_eq!(replayed.cursor(), 8);
}

/// Two notes under one commitment at two leaves, as two deposits of one amount at one deposit index
/// make. Each is held, each spends alone, and both survive a reopen.
#[test]
fn one_commitment_at_two_leaves_is_two_notes() {
    let dir = scratch("store-twin");
    let seed = phrase_to_seed(&generate_phrase().expect("entropy")).expect("seed");
    let path = dir.join("notes.log");
    let first = record(1000, 0);
    let twin =
        NoteRecord { leaf_index: 6, found_at: 6, plain: first.plain.clone(), ..record(0, 0) };
    let (mut log, _) = NoteLog::open(path.clone(), &seed).expect("open");
    log.append(&Row::Found(first)).expect("append");
    log.append(&Row::Found(twin)).expect("append");
    let (_, both) = NoteLog::open(path.clone(), &seed).expect("reopen");
    assert_eq!((both.balance(&ETH).spendable, both.balance(&ETH).note_count), (2000, 2));

    log.append(&Row::status(([0, 1, 2, 3], 6), NoteStatus::Spent)).expect("append");
    let (_, one) = NoteLog::open(path.clone(), &seed).expect("reopen");
    assert_eq!(one.balance(&ETH).spendable, 1000, "only the note at leaf 6 is spent");
    let left: Vec<u64> = one
        .held()
        .iter()
        .filter(|n| n.status == NoteStatus::Unspent)
        .map(|n| n.leaf_index)
        .collect();
    assert_eq!(left, vec![0]);

    // A row of the older kind names no leaf, and stands for every note under its commitment.
    let old = Row::Status { cm: [0, 1, 2, 3], leaf: None, status: NoteStatus::Pending };
    assert_eq!(old.encode()[0], 2, "the older kind is still written as it was");
    log.append(&old).expect("append");
    let (_, none) = NoteLog::open(path, &seed).expect("reopen");
    assert!(none.held().iter().all(|n| n.status == NoteStatus::Pending));
}

#[test]
fn each_asset_counts_only_its_own_notes() {
    let dir = scratch("store-assets");
    let seed = phrase_to_seed(&generate_phrase().expect("entropy")).expect("seed");
    let (mut log, _) = NoteLog::open(dir.join("notes.log"), &seed).expect("open");
    let rows = [
        Row::Found(record_of(ETH.id, 7_000, 0)),
        Row::Found(record_of(NOX.id, 3, 4)),
        Row::Found(record_of(NOX.id, 5, 8)),
        Row::Found(record_of(9, 1_000_000, 12)),
    ];
    for row in rows {
        log.append(&row).expect("append");
    }
    let (_reopened, state) = NoteLog::open(dir.join("notes.log"), &seed).expect("reopen");
    let (eth, nox) = (state.balance(&ETH), state.balance(&NOX));
    assert_eq!((eth.spendable, eth.note_count), (7_000, 1), "wei stays wei");
    assert_eq!((nox.spendable, nox.note_count), (8, 2), "no wei and no unknown asset in NOX");
}

#[test]
fn a_tampered_row_stops_the_replay() {
    let dir = scratch("store-tamper");
    let phrase = generate_phrase().expect("entropy");
    let seed = phrase_to_seed(&phrase).expect("seed");
    let path = dir.join("notes.log");
    let (mut log, _) = NoteLog::open(path.clone(), &seed).expect("open");
    log.append(&Row::Found(record(500, 0))).expect("append");

    let mut bytes = std::fs::read(&path).expect("read");
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&path, &bytes).expect("write");

    assert!(matches!(NoteLog::open(path, &seed), Err(StoreError::RowAuth)));
}
