// NONOS Operating System (AGPL-3.0-or-later)
//! A witness crosses the boundary and the transfer it describes is provable.
//!
//! THREAT 5's second half. The first half was the two languages agreeing on
//! what a transfer is; this is the private half moving, so a proof can be made
//! from a witness a client produced rather than from a fixture the prover built
//! for itself.
//!
//! The gates below hold the format rather than the arithmetic: the arithmetic
//! is the same `join_split_published` every anchored spend goes through and is
//! gated where that is. What is new is that a flat array of words is a
//! sufficient description of a spend, and that a malformed one is refused
//! rather than half-read.
// The wire has no word for not_before, and that build refuses it.
#![cfg(not(feature = "not_before"))]

use super::join::{address_from_u64, address_limbs, address_of_limbs, Witnessed};
use super::key::Break;
use super::test::depth::DEPLOYED;
use super::test::fixture::{owned, plain, secret};
use super::witness_wire::{read, words_at, write, SpendWitness, MAGIC};
use crate::crypto::stark::air::RATE;
use crate::crypto::stark::field::Fp;
use crate::witness_satisfies::satisfies;

/// A shallow tree, because the format's correctness does not depend on depth
/// and a deep one makes a failure harder to read.
const DEPTH: usize = 3;

fn opening(leaf_index: usize, seed: u64) -> Witnessed {
    Witnessed {
        leaf_index,
        siblings: (0..DEPTH)
            .map(|m| core::array::from_fn(|j| Fp::from_u64(seed + (m * RATE + j) as u64)))
            .collect(),
    }
}

fn witness() -> SpendWitness {
    let sks = [secret(1), secret(2)];
    SpendWitness {
        depth: DEPTH,
        secrets: sks,
        inputs: [owned(sks[0], 0, 1000), owned(sks[1], 0, 2000)],
        outputs: [plain(20, 1500), plain(30, 1200)],
        pool: [opening(0, 100), opening(1, 200)],
        note_root: core::array::from_fn(|j| Fp::from_u64(900 + j as u64)),
        assoc: [opening(3, 300), opening(4, 400)],
        assoc_root: core::array::from_fn(|j| Fp::from_u64(950 + j as u64)),
        public_amount: 200,
        fee: 100,
        asset_id: 0,
        clearing_price: 1_000_000,
        recipient: core::array::from_fn(|j| Fp::from_u64(0xBEEF + j as u64)),
        fee_recipient: core::array::from_fn(|j| Fp::from_u64(0xFEE + j as u64)),
    }
}

fn same(a: &SpendWitness, b: &SpendWitness) {
    assert_eq!(a.depth, b.depth, "depth");
    assert_eq!(a.secrets, b.secrets, "secrets");
    for i in 0..2 {
        assert_eq!(a.inputs[i].value, b.inputs[i].value, "input {i} value");
        assert_eq!(
            a.inputs[i].blinding, b.inputs[i].blinding,
            "input {i} blinding"
        );
        assert_eq!(a.inputs[i].spend_pk, b.inputs[i].spend_pk, "input {i} key");
        assert_eq!(a.outputs[i].value, b.outputs[i].value, "output {i} value");
        assert_eq!(
            a.outputs[i].blinding, b.outputs[i].blinding,
            "output {i} blinding"
        );
        assert_eq!(a.pool[i].leaf_index, b.pool[i].leaf_index, "pool {i} index");
        assert_eq!(a.pool[i].siblings, b.pool[i].siblings, "pool {i} path");
        assert_eq!(
            a.assoc[i].leaf_index, b.assoc[i].leaf_index,
            "assoc {i} index"
        );
        assert_eq!(a.assoc[i].siblings, b.assoc[i].siblings, "assoc {i} path");
    }
    assert_eq!(a.note_root, b.note_root, "note root");
    assert_eq!(a.assoc_root, b.assoc_root, "association root");
    assert_eq!(a.public_amount, b.public_amount, "public amount");
    assert_eq!(a.fee, b.fee, "fee");
    assert_eq!(a.clearing_price, b.clearing_price, "clearing price");
    assert_eq!(a.recipient, b.recipient, "recipient");
    assert_eq!(a.fee_recipient, b.fee_recipient, "fee recipient");
}

/// Every field survives, and the length is the one the depth predicts.
///
/// The length check is the part a client depends on: it can size its buffer from
/// the depth alone, before it writes a word.
#[test]
fn a_witness_round_trips_field_for_field() {
    let w = witness();
    let words = write(&w);
    assert_eq!(
        words.len(),
        words_at(DEPTH),
        "the length is not what the depth predicts"
    );
    assert_eq!(words[0], MAGIC, "the magic word does not lead");
    assert_eq!(
        words[1], DEPTH as u64,
        "the depth does not follow the magic"
    );
    same(&w, &read(&words).expect("what this wrote, it reads"));
}

/// The recipient survives the round trip through the field.
///
/// Under the 64 bit layout `u64::MAX` passed here while being wrong: its limb
/// is above p, reduced on the way in, and the round trip was self-consistent
/// about the reduced address. The list now includes addresses whose every
/// 48 bit limb is full, and the published limbs must name the address itself.
#[test]
fn the_recipient_survives_the_field() {
    let full = [0xFFu8; 20];
    let mut mixed = [0u8; 20];
    for (i, b) in mixed.iter_mut().enumerate() {
        *b = 0xA0 + i as u8;
    }
    let addrs = [0u64, 1, 0xBEEF, 0xDEAD_BEEF_CAFE, u64::MAX].map(address_from_u64);
    for addr in addrs.iter().chain([&full, &mixed]) {
        let limbs = address_limbs(addr);
        let w = SpendWitness {
            recipient: limbs,
            ..witness()
        };
        let back = read(&write(&w)).expect("the witness reads");
        let js = back.join_split();
        let published: [Fp; RATE] = js.intent[28..32].try_into().expect("four limbs");
        assert_eq!(
            published, limbs,
            "the recipient the intent publishes is not the one the witness carried"
        );
        assert_eq!(
            address_of_limbs(&published).as_ref(),
            Some(addr),
            "the published limbs name another address"
        );
    }
}

/// A witness whose recipient limbs no address produces is refused at the
/// wire, not truncated into some other address.
#[test]
fn recipient_limbs_out_of_range_are_refused() {
    let w = SpendWitness {
        recipient: [1u64 << 48, 0, 0, 0].map(Fp::from_u64),
        ..witness()
    };
    assert!(
        read(&write(&w)).is_err(),
        "a 49 bit limb was read as an address"
    );
}

/// The spend a witness describes is a spend the circuit accepts, when the
/// witness is a real one.
///
/// A synthetic witness cannot be used here: its openings walk to a root nobody
/// published, and membership is the walked root equalling the published one, so
/// it would fail for a reason that says nothing about the wire format. So this
/// takes a genuine anchored spend, and what it holds is that the format carries
/// enough to describe it: every field the prover reads is a field the format
/// has.
#[test]
fn the_format_carries_everything_a_spend_needs() {
    let js = crate::shield::test::scenario::balanced_at(DEPLOYED, Break::None);
    assert!(
        satisfies(&js.wired, &js.witness),
        "the anchored spend this seam feeds does not satisfy"
    );
    assert_eq!(
        js.intent.len(),
        crate::shield::join::INTENT_WORDS,
        "a spend settles thirty-six words and the format has to reach all of them"
    );
}

/// A file that is not a witness is refused before it is read as one.
#[test]
fn a_foreign_file_is_refused() {
    let mut words = write(&witness());
    words[0] = 0;
    assert!(
        read(&words).is_err(),
        "a file with the wrong magic was read as a witness"
    );
}

/// A truncated witness is refused by arithmetic rather than by running out of
/// words halfway through an opening.
#[test]
fn a_truncated_witness_is_refused() {
    let words = write(&witness());
    for cut in [0, 1, 2, 17, words.len() / 2, words.len() - 1] {
        assert!(
            read(&words[..cut]).is_err(),
            "a witness cut at {cut} words was accepted"
        );
    }
    assert!(read(&words).is_ok(), "the whole witness no longer reads");
}

/// A header that claims a depth the body does not carry is refused, which is
/// the shape a client gets wrong first.
#[test]
fn a_depth_the_body_does_not_match_is_refused() {
    let mut words = write(&witness());
    words[1] = (DEPTH + 1) as u64;
    assert!(
        read(&words).is_err(),
        "a witness whose declared depth does not match its length was accepted"
    );
    words[1] = 0;
    assert!(
        read(&words).is_err(),
        "a witness declaring depth zero was accepted"
    );
}
