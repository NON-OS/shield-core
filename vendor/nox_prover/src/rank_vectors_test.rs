// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(feature = "launch_v1")]
//! The wallet's per-proof rank certificate on every pinned wallet vector:
//! what a phone runs before a proof leaves, rerun on the bytes the wallets and
//! the contracts are tested against.

use crate::api::zk_fri_rank_check;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../spec/wallet-vectors");

fn publics(name: &str) -> Vec<u64> {
    let s = std::fs::read_to_string(format!("{DIR}/{name}/publics.json")).expect("publics");
    let open = s.find('[').unwrap_or(0) + 1;
    let close = s[open..].find(']').map(|i| open + i).unwrap_or(open);
    s[open..close]
        .split(',')
        .filter_map(|w| w.trim().parse().ok())
        .collect()
}

#[test]
#[ignore = "release tier: certifies the rank condition on three launch proofs"]
fn every_pinned_vector_carries_the_rank_condition() {
    for name in ["transfer-eth", "withdraw-eth", "transfer-nox"] {
        let proof = std::fs::read(format!("{DIR}/{name}/proof.bin")).expect("proof");
        let r = zk_fri_rank_check(&proof, &publics(name));
        println!("{name}: {r:?}");
        assert_eq!(r, Ok(()), "{name}");
    }
}
