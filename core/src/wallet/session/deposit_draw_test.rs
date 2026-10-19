// A test asserts by panicking, so the lints that forbid it are off here.
#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use super::super::Session;
use crate::custody::HardwareGuard;
use crate::error::CustodyError;
use crate::keys::DepositSite;
use crate::wallet::{prepare_deposit_at, Paths};

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

fn words() -> Vec<String> {
    let mut words = vec!["abandon".to_string(); 11];
    words.push("about".to_string());
    words
}

fn keep(s: &mut Session, index: u32, blinding: [u64; 4]) {
    let to = s.address();
    let note = prepare_deposit_at(&to, blinding, 10_000_000_000_000_000, 0, 50, 1)
        .expect("a deposit")
        .note;
    s.keep_deposit(index, note).expect("kept");
}

#[test]
fn a_deposit_index_is_never_drawn_twice() {
    let dir = std::env::temp_dir().join(format!("nox-draw-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a directory");
    let paths = Paths::under(&dir);
    let mut s = Session::restore(&paths, &Open, &words()).expect("restored");
    let first = s.draw_deposits(&SITE, 3, &[]).expect("drawn");
    assert_eq!(first.iter().map(|(i, _)| *i).collect::<Vec<_>>(), vec![0, 1, 2]);
    let again = s.draw_deposits(&SITE, 1, &[]).expect("drawn");
    assert_eq!(again, first[..1], "nothing kept, so the same index and blinding come back");
    let (index, blinding) = first[1];
    keep(&mut s, index, blinding);
    let held = s.draw_deposits(&SITE, 2, &[2]).expect("drawn");
    assert_eq!(
        held.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
        vec![3, 4],
        "past 1 and the held 2"
    );
    drop(s);
    let s = Session::unlock(&paths, &Open).expect("unlocked");
    assert_eq!(s.state().next_deposit(), 2, "the kept index survives a restart");
    std::fs::remove_dir_all(&dir).ok();
}

/// Kept in any order, every later draw is past every index kept, and blindings never repeat.
#[test]
fn every_draw_is_past_every_kept_index() {
    let dir = std::env::temp_dir().join(format!("nox-draw-order-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a directory");
    let paths = Paths::under(&dir);
    let mut s = Session::restore(&paths, &Open, &words()).expect("restored");
    let mut kept: Vec<u32> = Vec::new();
    let mut seen: Vec<[u64; 4]> = Vec::new();
    let mut state = 0x9e37_79b9_u32;
    for _ in 0..24 {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        let n = (state >> 16) as usize % 3 + 1;
        let drawn = s.draw_deposits(&SITE, n, &[]).expect("drawn");
        assert!(drawn.iter().all(|(i, _)| kept.iter().all(|k| i > k)));
        let (index, blinding) = drawn[(state >> 8) as usize % drawn.len()];
        assert!(!seen.contains(&blinding));
        seen.push(blinding);
        keep(&mut s, index, blinding);
        kept.push(index);
    }
    std::fs::remove_dir_all(&dir).ok();
}
