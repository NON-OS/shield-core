// NONOS Operating System (AGPL-3.0-or-later)
//! Format 6 from the prover: the pinned transfer proved from its request, seed
//! and entropy, re-encoded with shared paths, and verified in that form.
//!
//! Built plain it proves the 24-byte launch proof, which must be the pinned
//! bytes exactly. Built with `digest32` it proves the same spend with every
//! digest whole, which is the 32-byte digest question: what 32-byte digests cost once
//! the paths are shared.

use crate::api::{prove_inner, share_under, verify_shared_under, Error, Options};
use stark_proofs::crypto::stark::merkle::{TreeTop, DIGEST_BYTES};

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../spec/wallet-vectors/transfer-eth"
);

fn read(name: &str) -> String {
    std::fs::read_to_string(format!("{DIR}/{name}")).expect("a pinned vector file")
}

fn entropy() -> Vec<u8> {
    let hex = read("entropy.hex");
    let hex = hex.trim();
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

#[test]
#[ignore = "release tier: proves the pinned transfer from scratch"]
fn the_pinned_transfer_in_format_six() {
    let (proof, cache) = prove_inner(
        &read("request.json"),
        &read("seed.json"),
        &entropy(),
        None,
        &Options::default(),
    )
    .expect("the pinned transfer proves");
    let root = TreeTop::from_bytes(&cache)
        .expect("the prover's own cache")
        .root();
    let shared = share_under(&proof.bytes, &proof.publics, &root).expect("the proof re-encodes");
    assert_eq!(verify_shared_under(&shared, &proof.publics, &root), Ok(()));

    let mut flipped = shared.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    assert!(matches!(
        verify_shared_under(&flipped, &proof.publics, &root),
        Err(Error::NotVerified(_))
    ));

    let hex: String = root[..DIGEST_BYTES]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    println!(
        "digest {DIGEST_BYTES} bytes: format 5 {} bytes, format 6 {} bytes, {} saved; periodic root {hex}",
        proof.bytes.len(),
        shared.len(),
        proof.bytes.len() - shared.len()
    );

    /*
     * With NOX_SHARED_OUT set, the artifacts a chain verifier is tested on:
     * the format 6 bytes, the public words and the periodic root it holds.
     */
    if let Ok(out) = std::env::var("NOX_SHARED_OUT") {
        std::fs::create_dir_all(&out).expect("the output directory");
        std::fs::write(format!("{out}/proof.bin"), &shared).expect("write the proof");
        let words: Vec<String> = proof.publics.iter().map(u64::to_string).collect();
        let json = format!(
            "{{\"format\": 6, \"digest_bytes\": {DIGEST_BYTES}, \"periodic_root\": \"{hex}\", \"publics\": [{}]}}\n",
            words.join(", ")
        );
        std::fs::write(format!("{out}/publics.json"), json).expect("write the publics");
    }

}
