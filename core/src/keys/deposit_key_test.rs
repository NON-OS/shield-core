// A test asserts by panicking, so the lints that forbid it are off here.
#![allow(clippy::expect_used)]

use super::DepositKey;
use crate::custody::Seed;
use crate::keys::material::Material;
use crate::keys::{Account, DepositSite};
use nonos_stark::field::P;

const SITE: DepositSite = DepositSite { chain_id: 11_155_111, pool: [0xae; 20] };

fn key(seed: u8, account: u32) -> DepositKey {
    let material = Material::of(&Seed::new([seed; 64]), account);
    DepositKey::from_material(material.bytes(), account)
}

#[test]
fn the_same_words_give_the_same_blinding() {
    let a = key(7, 0).blinding(&SITE, 3).expect("a blinding");
    let b = key(7, 0).blinding(&SITE, 3).expect("a blinding");
    assert_eq!(a, b);
    let account = Account::at(&Seed::new([7; 64]), 0).expect("an account");
    assert_eq!(account.deposit_key().blinding(&SITE, 3).expect("a blinding"), a);
}

#[test]
fn every_input_moves_the_blinding() {
    let base = key(7, 0).blinding(&SITE, 0).expect("a blinding");
    let other_chain = DepositSite { chain_id: 1, ..SITE };
    let other_pool = DepositSite { pool: [0xaf; 20], ..SITE };
    let moved = [
        key(7, 0).blinding(&SITE, 1),
        key(7, 1).blinding(&SITE, 0),
        key(8, 0).blinding(&SITE, 0),
        key(7, 0).blinding(&other_chain, 0),
        key(7, 0).blinding(&other_pool, 0),
    ];
    for m in moved {
        assert_ne!(m.expect("a blinding"), base);
    }
}

#[test]
fn every_blinding_word_is_canonical() {
    let k = key(9, 2);
    for index in 0..256 {
        let words = k.blinding(&SITE, index).expect("a blinding");
        assert!(words.iter().all(|w| *w < P), "index {index}");
    }
}

/// The blinding of deposits 0 and 1 of accounts 0 and 1 of the phrase "abandon" eleven times then
/// "about", at the production pool on Sepolia. A change here strands every deposit made so far.
#[test]
fn the_vectors_hold() {
    let seed = crate::keys::accounts_test::seed();
    let pool = [
        0xae, 0xe5, 0x1e, 0x82, 0x96, 0x5e, 0xc1, 0xde, 0xd8, 0x70, 0xf3, 0xf4, 0xc2, 0x48, 0xad,
        0x4a, 0xdd, 0xc3, 0xe1, 0xcb,
    ];
    let site = DepositSite { chain_id: 11_155_111, pool };
    let expected = [
        (0, 0, "2b6ef0e0903b933420d63051a8671a53569e9499c929bcd5b625ef8a24ab5391"),
        (0, 1, "7f872a867f5db5c190d8244e99478c610be08bb3c45e6ff40949d62d9be4f6a2"),
        (1, 0, "ff694c64e5fd1ba09c340298d222df14d5e532216d28f11173b82fc7fd2147ff"),
        (1, 1, "ea29e76a619c578156ecda48f09aeb8eb87daff775f0067149a25bd9850edcbb"),
    ];
    let got: Vec<(u32, u32, String)> = expected
        .iter()
        .map(|(account, index, _)| {
            let a = Account::at(&seed, *account).expect("an account");
            let words = a.deposit_key().blinding(&site, *index).expect("a blinding");
            (*account, *index, words.iter().map(|w| format!("{w:016x}")).collect())
        })
        .collect();
    let want: Vec<(u32, u32, String)> =
        expected.iter().map(|(a, i, hex)| (*a, *i, (*hex).to_string())).collect();
    assert_eq!(got, want, "account, deposit, blinding");
}

#[test]
fn the_key_prints_nothing() {
    assert_eq!(format!("{:?}", key(7, 0)), "DepositKey(redacted)");
}
