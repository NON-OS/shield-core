// Tests assert by panicking, so those lints are off here only.
#![allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

//! A proof made in a browser, cut into the arguments of the production verifier's `verifyBatch`:
//! the single-call layout and the 13 pool words. `WEB_PROOF` is the proof JSON the page returned,
//! `WEB_CACHE` the periodic cache it proved from, and `WEB_ARGS_OUT` the folder the two files go
//! to, for `web/bench/verifier-call.sh`.

use nox_shield_core::prover::launch::publics::{pool_words, LIMBS};
use nox_shield_core::wallet::one_call;

fn field<'a>(json: &'a str, name: &str) -> &'a str {
    let start = json.find(&format!("\"{name}\": ")).expect(name) + name.len() + 4;
    let rest = &json[start..];
    let end = rest.find(if rest.starts_with('[') { ']' } else { ',' }).expect(name);
    &rest[..=end]
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
#[ignore = "needs a proof from the browser bench"]
fn a_browser_proof_cuts_to_the_verifier_arguments() {
    let json =
        std::fs::read_to_string(std::env::var("WEB_PROOF").expect("WEB_PROOF")).expect("proof");
    let cache = std::fs::read(std::env::var("WEB_CACHE").expect("WEB_CACHE")).expect("cache");
    let out = std::env::var("WEB_ARGS_OUT").expect("WEB_ARGS_OUT");
    let digits =
        field(&json, "proof").trim_matches(|c| c == '"' || c == ',').trim_start_matches("0x");
    let proof: Vec<u8> = (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).expect("hex"))
        .collect();
    let publics: Vec<u64> = field(&json, "publics")
        .trim_matches(|c| c == '[' || c == ']')
        .split(", ")
        .map(|w| w.parse().expect("a limb"))
        .collect();
    let shared = nox_prover::to_shared(&proof, &publics, &cache).expect("the shared form");
    nox_prover::verify_shared(&shared, &publics, &cache).expect("it verifies");
    let limbs: [u64; LIMBS] = publics.try_into().expect("37 limbs");
    let whole = one_call(&shared).expect("it cuts");
    let words: Vec<String> = pool_words(&limbs).iter().map(|w| hex(w)).collect();
    std::fs::write(format!("{out}/whole.hex"), hex(&whole)).expect("out");
    std::fs::write(format!("{out}/words.txt"), words.join("\n")).expect("out");
    println!("{} bytes in the single call, {} words", whole.len(), words.len());
}
