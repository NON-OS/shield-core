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
        (0, 0, "63c512c68338b9ce6a502bf3ba4e5a2df46bd28e8a7e4196d896c55b3f5ba88d"),
        (0, 1, "50d705c61ab2c3e65e5acb0829c5d16b659e601ad27f2a2d41f93e57d3702174"),
        (1, 0, "b4091403d3a5bdf3dbeddc599f4716e932a9f64c4b5cb343af201ed975a98568"),
        (1, 1, "e3a040c1855a76b0e1fa76140f8e24deb299aa818880947e6ac3f04815f51f8c"),
    ];
    for (account, index, hex) in expected {
        let a = Account::at(&seed, account).expect("an account");
        let words = a.deposit_key().blinding(&site, index).expect("a blinding");
        let got: String = words.iter().map(|w| format!("{w:016x}")).collect();
        assert_eq!(got, hex, "account {account}, deposit {index}");
    }
}

#[test]
fn the_key_prints_nothing() {
    assert_eq!(format!("{:?}", key(7, 0)), "DepositKey(redacted)");
}
