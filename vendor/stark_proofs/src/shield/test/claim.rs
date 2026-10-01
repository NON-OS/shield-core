// NONOS Operating System (AGPL-3.0-or-later)
//! Words 36 and 37 of the claim statement: the two input notes' limb sums,
//! wired to the balance region's running sums after the input legs. The
//! inputs' total is `lo + hi * 2^32`, and each word is bound to its own cell,
//! so a proof made for one pair does not verify for another, not even for a
//! pair with the same total.
#![cfg(feature = "claim")]

use crate::crypto::stark::air::{stark_prove_ext_rounds, stark_verify_ext_rounds_why};
use crate::crypto::stark::field::Fp;
use crate::crypto::stark::fri::FRI_FOLD_LOG;
use crate::host::{build_parts_with, Entropy};
use crate::recursion_assembly::inner::{hasher, hide_at};
use crate::shield::batch::assemble;
use crate::shield::join::publics::{INPUT_SUM_HI, INPUT_SUM_LO, WORDS};
use crate::shield::join::{join_split_shape, JoinSplit};
use crate::shield::member::TREE_DEPTH;
use crate::shield_params::direct;

const VECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../spec/wallet-vectors/transfer-eth"
);
const SHIFT: u64 = 1 << 32;

fn read(name: &str) -> String {
    std::fs::read_to_string(format!("{VECTOR}/{name}")).expect("pinned wallet vector")
}

fn entropy_bytes() -> Vec<u8> {
    let hex = read("entropy.hex");
    let hex = hex.trim();
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

/// The two input values the pinned seed holds.
fn input_values() -> [u64; 2] {
    let seed = read("seed.json");
    let values: Vec<u64> = seed
        .match_indices("\"value\": ")
        .map(|(at, key)| {
            let rest = &seed[at + key.len()..];
            let end = rest
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(rest.len());
            rest[..end].parse().expect("a value")
        })
        .collect();
    [values[0], values[1]]
}

fn build() -> JoinSplit {
    let bytes = entropy_bytes();
    let mut e = Entropy::new(&bytes);
    let mut w = |n: usize| e.words(n);
    let (parts, _) = build_parts_with(&read("request.json"), &read("seed.json"), &mut w)
        .expect("the pinned request");
    let mut b = assemble(vec![parts.parts]);
    let intent = b.intents.pop().expect("one statement");
    JoinSplit {
        wired: b.wired,
        witness: b.witness,
        intent,
    }
}

#[test]
fn words_36_and_37_are_the_input_limb_sums() {
    let js = build();
    assert_eq!(WORDS, 38);
    assert_eq!(js.intent.len(), WORDS);
    let [a, b] = input_values();
    let (lo, hi) = (
        js.intent[INPUT_SUM_LO].to_u64(),
        js.intent[INPUT_SUM_HI].to_u64(),
    );
    assert_eq!(lo, (a & (SHIFT - 1)) + (b & (SHIFT - 1)));
    assert_eq!(hi, (a >> 32) + (b >> 32));
    assert_eq!(
        lo as u128 + hi as u128 * SHIFT as u128,
        a as u128 + b as u128,
        "the words rebuild the inputs' total"
    );
    assert!(
        lo < 1 << 33 && hi < 1 << 33,
        "an honest claim passes the pool's range check"
    );
}

/// Proved once, the proof verifies with its own sums and is refused with
/// either moved by one, and with the pair moved to another pair of the same
/// total: each word is tied to its own cell, not only the sum they make.
#[test]
fn a_proof_does_not_verify_under_other_sums() {
    let (q, grind, extra) = (
        direct::N_QUERIES,
        direct::GRIND_BITS,
        direct::EXTRA_BLOWUP_BITS,
    );
    let mut js = build();
    let bytes = entropy_bytes();
    let mut e = Entropy::new(&bytes);
    let w = e.words(4).expect("entropy");
    let blind = hide_at(
        &hasher(),
        &mut js,
        &[w[0], w[1], w[2], w[3]],
        q,
        1usize << FRI_FOLD_LOG,
    );
    let publics = js.intent.clone();
    let mut witness = js.witness;
    let (rounds, tree, _) = stark_prove_ext_rounds(
        js.wired,
        &mut witness,
        q,
        grind,
        extra,
        &publics,
        None,
        &blind,
    )
    .expect("the honest proof");
    let verdict = |words: &[Fp]| {
        stark_verify_ext_rounds_why(
            join_split_shape(TREE_DEPTH, words),
            &rounds,
            q,
            grind,
            extra,
            &tree.root(),
            words,
        )
    };
    assert!(
        verdict(&publics).is_ok(),
        "the honest claim does not verify"
    );

    let (lo, hi) = (publics[INPUT_SUM_LO], publics[INPUT_SUM_HI]);
    let one = Fp::ONE;
    let shift = Fp::from_u64(SHIFT);
    let moved: [(Fp, Fp); 5] = [
        (lo + one, hi),
        (lo - one, hi),
        (lo, hi + one),
        (lo, hi - one),
        (lo + shift, hi - one),
    ];
    for (l, h) in moved {
        let mut words = publics.clone();
        words[INPUT_SUM_LO] = l;
        words[INPUT_SUM_HI] = h;
        assert!(
            verdict(&words).is_err(),
            "the claim verified with its sums moved to ({l:?}, {h:?})"
        );
    }
}
