// A test asserts by panicking, so the lints that forbid it are off here.
#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use super::super::Session;
use super::RESERVED_FOR;
use crate::custody::HardwareGuard;
use crate::error::{CustodyError, WalletError};
use crate::keys::DepositSite;
use crate::store::Row;
use crate::wallet::{prepare_deposit_at, Paths};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SITE: DepositSite = DepositSite { chain_id: 11_155_111, pool: [0xae; 20] };

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
    let dir = std::env::temp_dir().join(format!("nox-draw-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).expect("a directory");
    let mut words = vec!["abandon".to_string(); 11];
    words.push("about".to_string());
    let s = Session::restore(&Paths::under(&dir), &Open, &words).expect("restored");
    (dir, s)
}

fn keep(s: &mut Session, index: u32, blinding: [u64; 4], stamp: u64) -> Result<(), WalletError> {
    let to = s.address();
    let note = prepare_deposit_at(&to, blinding, 10_000_000_000_000_000, 0, 50, 1)
        .expect("a deposit")
        .note;
    s.keep_deposit(index, note, stamp)
}

/// The deposit with `blinding` found in the pool at `leaf`, as a sync records it.
fn seen_in_pool(s: &mut Session, blinding: [u64; 4], leaf: u64) {
    let to = s.address();
    let plain = prepare_deposit_at(&to, blinding, 10_000_000_000_000_000, 0, 50, 1)
        .expect("a deposit")
        .note;
    let cm =
        crate::notes::commitment(&crate::prover::pool_hasher(), &plain.note()).map(|f| f.value());
    let status = crate::notes::NoteStatus::Unspent;
    let record = crate::notes::NoteRecord { plain, leaf_index: leaf, cm, status, found_at: leaf };
    s.record(Row::Found(record)).expect("found");
}

fn indices(drawn: &[(u32, [u64; 4])]) -> Vec<u32> {
    drawn.iter().map(|(i, _)| *i).collect()
}

#[test]
fn a_kept_index_is_never_drawn_again() {
    let (dir, mut s) = restored("kept");
    let now = Instant::now();
    let first = s.draw_deposits(&SITE, 3, now).expect("drawn");
    assert_eq!(indices(&first.drawn), vec![0, 1, 2]);
    let second = s.draw_deposits(&SITE, 1, now).expect("drawn");
    assert_eq!(indices(&second.drawn), vec![3], "past the three a review holds");
    let (index, blinding) = first.drawn[1];
    keep(&mut s, index, blinding, first.stamp).expect("kept");
    s.release_deposits(first.id);
    let again = s.draw_deposits(&SITE, 2, now).expect("drawn");
    assert_eq!(indices(&again.drawn), vec![0, 2], "the released ones, never the kept one");
    assert_eq!(again.drawn[0], first.drawn[0], "an index has one blinding");
    drop(s);
    let mut s = Session::unlock(&Paths::under(&dir), &Open).expect("unlocked");
    assert!(s.state().deposit_used(1), "the kept index survives a restart");
    let after = s.draw_deposits(&SITE, 2, now).expect("drawn");
    assert_eq!(indices(&after.drawn), vec![0, 2]);
    std::fs::remove_dir_all(&dir).ok();
}

/// Reviews drawn from many threads at once never hold one index.
#[test]
fn reviews_drawn_at_once_never_share_an_index() {
    let (dir, s) = restored("threads");
    let s = Arc::new(Mutex::new(s));
    let runs: Vec<_> = (0..8)
        .map(|_| {
            let s = Arc::clone(&s);
            std::thread::spawn(move || {
                let mut drawn = Vec::new();
                for _ in 0..4 {
                    let mut s = s.lock().expect("the session");
                    let draw = s.draw_deposits(&SITE, 2, Instant::now()).expect("drawn");
                    drawn.extend(indices(&draw.drawn));
                }
                drawn
            })
        })
        .collect();
    let mut all: Vec<u32> = runs.into_iter().flat_map(|r| r.join().expect("a thread")).collect();
    all.sort_unstable();
    assert_eq!(all, (0..64).collect::<Vec<u32>>(), "64 indices, each once");
    std::fs::remove_dir_all(&dir).ok();
}

/// A review's yes is refused when a deposit kept or found since its draw took its index, as a sync
/// that found another device's deposit does.
#[test]
fn a_yes_is_refused_when_its_index_was_taken_since() {
    let (dir, mut s) = restored("taken");
    let now = Instant::now();
    let review = s.draw_deposits(&SITE, 1, now).expect("drawn");
    let (index, blinding) = review.drawn[0];
    s.record(Row::DepositIndex(index)).expect("a sync found it on chain");
    let refused = keep(&mut s, index, blinding, review.stamp);
    assert!(matches!(refused, Err(WalletError::ReviewExpired)));

    // A reservation outlived, its index drawn again: the second yes wins, the first is refused.
    let late = now + RESERVED_FOR + Duration::from_secs(1);
    let old = s.draw_deposits(&SITE, 1, now).expect("drawn");
    let new = s.draw_deposits(&SITE, 1, late).expect("drawn");
    assert_eq!(old.drawn, new.drawn, "the expired reservation is drawn again");
    let (index, blinding) = new.drawn[0];
    keep(&mut s, index, blinding, new.stamp).expect("kept");
    let refused = keep(&mut s, index, blinding, old.stamp);
    assert!(matches!(refused, Err(WalletError::ReviewExpired)));
    std::fs::remove_dir_all(&dir).ok();
}

/// Kept in any order and each seen in the pool, a draw never returns an index used or held, and
/// blindings never repeat.
#[test]
fn a_draw_never_returns_an_index_used_or_held() {
    let (dir, mut s) = restored("order");
    let now = Instant::now();
    let mut held: Vec<u32> = Vec::new();
    let mut seen: Vec<[u64; 4]> = Vec::new();
    let mut state = 0x9e37_79b9_u32;
    for _ in 0..24 {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        let n = (state >> 16) as usize % 3 + 1;
        let draw = s.draw_deposits(&SITE, n, now).expect("drawn");
        for (i, _) in &draw.drawn {
            assert!(!s.state().deposit_used(*i) && !held.contains(i));
        }
        let (index, blinding) = draw.drawn[(state >> 8) as usize % draw.drawn.len()];
        assert!(!seen.contains(&blinding));
        seen.push(blinding);
        keep(&mut s, index, blinding, draw.stamp).expect("kept");
        seen_in_pool(&mut s, blinding, u64::from(index));
        if state & 1 == 0 {
            s.release_deposits(draw.id);
        } else {
            held.extend(indices(&draw.drawn).into_iter().filter(|i| *i != index));
        }
    }
    std::fs::remove_dir_all(&dir).ok();
}
