// NONOS Operating System (AGPL-3.0-or-later)
//! Word 36, the earliest settlement time: carried from the request into the
//! statement, on its grid, and bound, so a proof made for one time does not
//! verify for another. Only in the `not_before` build, whose statement has the
//! word; the 36-word circuit is unchanged.
#![cfg(feature = "not_before")]

use crate::crypto::stark::air::{stark_prove_ext_rounds, stark_verify_ext_rounds_why};
use crate::crypto::stark::field::Fp;
use crate::crypto::stark::fri::FRI_FOLD_LOG;
use crate::host::{build_parts_with, Entropy};
use crate::recursion_assembly::inner::{hasher, hide_at};
use crate::shield::batch::assemble;
use crate::shield::join::publics::{NOT_BEFORE, NOT_BEFORE_GRID_S, WORDS};
use crate::shield::join::{join_split_shape, JoinSplit};
use crate::shield::member::TREE_DEPTH;
use crate::shield_params::direct;

const VECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../spec/wallet-vectors/transfer-eth"
);
const T: u64 = 1_790_000_400;

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

/// The pinned request with `not_before` set, or left out when `t` is `None`.
fn request(t: Option<u64>) -> String {
    let r = read("request.json");
    match t {
        Some(t) => r.replacen('{', &format!("{{\"not_before\": {t}, "), 1),
        None => r,
    }
}

fn build(t: Option<u64>) -> Result<JoinSplit, String> {
    let bytes = entropy_bytes();
    let mut e = Entropy::new(&bytes);
    let mut w = |n: usize| e.words(n);
    let (parts, _) = build_parts_with(&request(t), &read("seed.json"), &mut w)?;
    let mut b = assemble(vec![parts.parts]);
    let intent = b.intents.pop().ok_or("no statement")?;
    Ok(JoinSplit {
        wired: b.wired,
        witness: b.witness,
        intent,
    })
}

#[test]
fn a_request_without_or_off_the_grid_is_refused() {
    let missing = build(None).err().unwrap_or_default();
    assert!(
        missing.contains("not_before"),
        "a request without not_before was not refused: {missing}"
    );
    let off = build(Some(T + 1)).err().unwrap_or_default();
    assert!(
        off.contains("multiple of 600"),
        "an off-grid not_before was not refused: {off}"
    );
    let zero = build(Some(0)).err().unwrap_or_default();
    assert!(
        zero.contains("not_before"),
        "a zero not_before was not refused: {zero}"
    );
    assert_eq!(T % NOT_BEFORE_GRID_S, 0);
}

#[test]
fn word_36_is_the_requested_time() {
    let js = build(Some(T)).expect("the request on the grid");
    assert_eq!(js.intent.len(), WORDS);
    assert_eq!(WORDS, 37);
    assert_eq!(js.intent[NOT_BEFORE], Fp::from_u64(T));
}

/// Proved at T, the proof verifies at T and is refused at T + 600 and at 0: a
/// lander cannot move the time, earlier or later, without the proof failing.
#[test]
fn a_proof_does_not_verify_under_another_not_before() {
    let (q, grind, extra) = (
        direct::N_QUERIES,
        direct::GRIND_BITS,
        direct::EXTRA_BLOWUP_BITS,
    );
    let mut js = build(Some(T)).expect("the request on the grid");
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
        "the honest proof at T does not verify"
    );
    for moved in [T + NOT_BEFORE_GRID_S, T - NOT_BEFORE_GRID_S, 0] {
        let mut words = publics.clone();
        words[NOT_BEFORE] = Fp::from_u64(moved);
        assert!(
            verdict(&words).is_err(),
            "the proof verified with not_before moved to {moved}"
        );
    }
}
