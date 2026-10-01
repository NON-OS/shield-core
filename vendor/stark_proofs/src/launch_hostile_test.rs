// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(feature = "launch_v1")]
//! The launch verifier against bytes it did not make.
//!
//! Wallets, relayers and anyone checking a settlement parse proofs from
//! strangers. Two properties, on the pinned transfer: nothing here panics,
//! and no altered proof verifies. A flipped bit that still verified would be
//! malleability: a relayer could change a proof in flight and the pool would
//! take it. Every section of the 112,956 bytes is reached, the header byte by
//! byte and the body at a fixed stride.

use crate::crypto::stark::air::{periodic_root, stark_verify_ext_rounds_why};
use crate::crypto::stark::field::Fp;
use crate::proof_wire::{deserialize_rounds, ParamSet, HEADER_BYTES};
use crate::shield::join::join_split_shape;
use crate::shield::member::TREE_DEPTH;
use crate::shield_params::direct;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::OnceLock;

const PROOF: &[u8] = include_bytes!("../../spec/wallet-vectors/transfer-eth/proof.bin");
const PUBLICS: &str = include_str!("../../spec/wallet-vectors/transfer-eth/publics.json");

/// The launch circuit's periodic root, first 24 bytes: docs/13-launch.md.
const ROOT_24: &str = "bb7614937ae6d7e5e26e88610fae8ff9e5195fef4721fdbd";

fn words() -> Vec<Fp> {
    let open = PUBLICS.find('[').unwrap_or(0) + 1;
    let close = PUBLICS[open..].find(']').map(|i| open + i).unwrap_or(open);
    PUBLICS[open..close]
        .split(',')
        .filter_map(|w| w.trim().parse().ok())
        .map(Fp::from_u64)
        .collect()
}

fn root() -> &'static [u8; 32] {
    static ROOT: OnceLock<[u8; 32]> = OnceLock::new();
    ROOT.get_or_init(|| {
        periodic_root(
            &join_split_shape(TREE_DEPTH, &words()),
            direct::EXTRA_BLOWUP_BITS,
        )
    })
}

/// The whole launch check: parse at the launch point, then verify. `Err` for
/// a refusal, and a panic is caught and reported as a failure of the test.
fn verdict(bytes: &[u8], w: &[Fp]) -> Result<(), String> {
    let (q, grind, extra) = (
        direct::N_QUERIES,
        direct::GRIND_BITS,
        direct::EXTRA_BLOWUP_BITS,
    );
    let run = || {
        let air = join_split_shape(TREE_DEPTH, w);
        let params = ParamSet::of(&air, q, grind, extra);
        let rounds =
            deserialize_rounds(bytes, &params).ok_or_else(|| "does not parse".to_string())?;
        stark_verify_ext_rounds_why(air, &rounds, q, grind, extra, root(), w)
            .map_err(|why| why.to_string())
    };
    match catch_unwind(AssertUnwindSafe(run)) {
        Ok(v) => v,
        Err(_) => panic!("the launch check panicked on {} bytes", bytes.len()),
    }
}

#[test]
fn the_pinned_proof_verifies_under_the_launch_root() {
    let hex: String = root()[..24].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, ROOT_24, "the periodic root moved");
    assert_eq!(PROOF.len(), 112_956);
    assert_eq!(verdict(PROOF, &words()), Ok(()));
}

/// Every header byte, then a stride through the body: one flipped bit each,
/// low bit and high bit alternating, and not one of them may verify.
#[test]
fn no_single_flipped_bit_verifies() {
    let w = words();
    let body = PROOF.len() - HEADER_BYTES;
    let mut at: Vec<usize> = (0..HEADER_BYTES).collect();
    at.extend((0..160).map(|k| HEADER_BYTES + k * body / 160 + (k * 7919) % (body / 160)));
    for (n, &i) in at.iter().enumerate() {
        let mut b = PROOF.to_vec();
        b[i] ^= if n % 2 == 0 { 0x01 } else { 0x80 };
        assert!(
            verdict(&b, &w).is_err(),
            "byte {i} flipped and the proof still verified"
        );
    }
}

#[test]
fn a_cut_or_padded_proof_does_not_verify() {
    let w = words();
    for len in [
        0,
        1,
        HEADER_BYTES - 1,
        HEADER_BYTES,
        HEADER_BYTES + 1,
        PROOF.len() / 2,
        PROOF.len() - 1,
    ] {
        assert!(
            verdict(&PROOF[..len], &w).is_err(),
            "a proof cut to {len} bytes verified"
        );
    }
    let mut longer = PROOF.to_vec();
    longer.push(0);
    assert!(
        verdict(&longer, &w).is_err(),
        "a proof with a byte appended verified"
    );
}

/// The statement is the 36 words: each one changed is a different statement.
#[test]
fn no_changed_public_word_verifies() {
    let base = words();
    for i in 0..base.len() {
        let mut w = base.clone();
        w[i] = w[i] + Fp::ONE;
        assert!(
            verdict(PROOF, &w).is_err(),
            "public word {i} changed and the proof still verified"
        );
    }
}
