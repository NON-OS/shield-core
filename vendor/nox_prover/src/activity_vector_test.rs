// NONOS Operating System (AGPL-3.0-or-later)
//! The wallet's activity vector, reproduced from its files through the entry
//! point the wallet calls: the answer must come out byte for byte.

use crate::activity::{prove_activity, to_json};

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../spec/wallet-vectors-activity/claim"
);

fn read(name: &str) -> String {
    std::fs::read_to_string(format!("{DIR}/{name}")).expect("a pinned vector file")
}

#[test]
#[ignore = "release tier: one activity proof, about 30 s"]
fn the_wallet_activity_vector_reproduces() {
    let hex = read("entropy.hex");
    let hex = hex.trim();
    let entropy: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex"))
        .collect();
    let (proof, publics) =
        prove_activity(&read("request.json"), &read("seed.json"), &entropy).expect("proves");
    assert_eq!(to_json(&proof, &publics) + "\n", read("answer.json"));
}

/// A request whose leaves do not fold to its root is refused before proving.
#[test]
fn a_week_that_does_not_fold_to_its_root_is_refused() {
    let request = read("request.json");
    let at = request.find("\"root\": \"0x").expect("a root") + 12;
    let flipped = if &request[at..at + 1] == "0" {
        "1"
    } else {
        "0"
    };
    let bad = format!("{}{}{}", &request[..at], flipped, &request[at + 1..]);
    let err = prove_activity(&bad, &read("seed.json"), &[7u8; 64]).expect_err("refused");
    assert!(err.contains("do not fold"), "{err}");
}

/// P from an address as `PayoutAddress.encode` writes it: the contracts'
/// example, `address(11 | 12 << 48 | 13 << 96 | 14 << 144)`, is the pinned
/// proofs' [11, 12, 13, 14]; the zero address and a short one are refused.
#[test]
fn the_payout_is_the_address_in_48_48_48_16_bit_limbs() {
    use crate::activity::payout_words;
    use stark_proofs::crypto::stark::field::Fp;
    let p =
        payout_words("0x000e00000000000d00000000000c00000000000b").map(|w| w.map(|v| v.to_u64()));
    assert_eq!(p, Ok([11, 12, 13, 14]));
    let top = payout_words("0xffffffffffffffffffffffffffffffffffffffff").expect("an address");
    assert_eq!(
        top.map(|v| v.to_u64()),
        [(1 << 48) - 1, (1 << 48) - 1, (1 << 48) - 1, (1 << 16) - 1]
    );
    assert!(top.iter().all(|&v| v != Fp::ZERO));
    assert!(payout_words("0x0000000000000000000000000000000000000000").is_err());
    assert!(payout_words("0x1234").is_err());
}
