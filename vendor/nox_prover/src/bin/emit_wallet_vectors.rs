// NONOS Operating System (AGPL-3.0-or-later)
//! Pinned wallet vectors: a request, a seed file and fixed entropy, and the
//! proof and public words `nox_prover::prove_with` makes from them.
//!
//!     emit_wallet_vectors <out-dir> <periodic.top>
//!
//! Three spends against one fixture pool of the pool's own shape: an ETH
//! transfer to a payee through a submitter, an ETH withdrawal to a fixed
//! address through a submitter, and a NOX transfer, whose note unit is 10^9
//! base units. The notes descend from small seeds (`shield::test::fixture`),
//! so the secrets are fixtures and spend nothing real. The entropy is the
//! 512 bytes `(7 i + 3) mod 256`: fixed, so the proof is too, and Rust, Zig,
//! iOS and the contracts can check the same bytes. Each proof is verified
//! and its zero-knowledge rank condition checked before it is written.

use nox_prover::{prove_with, to_json, verify, zk_fri_rank_check, Options, ENTROPY_BYTES};
use stark_proofs::crypto::stark::air::{Poseidon, RATE};
use stark_proofs::crypto::stark::field::Fp;
use stark_proofs::crypto::stark::hash::keccak256;
use stark_proofs::host::pack_u256;
use stark_proofs::shield::key::derive;
use stark_proofs::shield::member::{PoolTree, TREE_DEPTH};
use stark_proofs::shield::note::{note_parts, Note, POOL_LOG_ROUNDS};
use stark_proofs::shield::test::fixture::{owned, secret};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn note_json(n: &Note) -> String {
    format!(
        "{{\"value\": {}, \"asset_id\": {}, \"spend_pk\": {:?}, \"blinding\": {:?}}}",
        n.value, n.asset_id, n.spend_pk, n.blinding
    )
}

struct Case {
    name: &'static str,
    asset: u64,
    input: u64,
    public_amount: u64,
    fee: u64,
    outputs: [u64; 2],
    /// Output 0 to the payee's key, or both to the spender.
    to_payee: bool,
    recipient: &'static str,
    clearing_price: u64,
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (Some(out), Some(cache_path)) = (a.first(), a.get(1)) else {
        eprintln!("usage: emit_wallet_vectors <out-dir> <periodic.top>");
        std::process::exit(2)
    };
    let cache = std::fs::read(cache_path).unwrap_or_else(|e| {
        eprintln!("cannot read {cache_path}: {e}");
        std::process::exit(2)
    });
    std::fs::create_dir_all(out).unwrap_or_else(|e| {
        eprintln!("cannot create {out}: {e}");
        std::process::exit(2)
    });
    let entropy: Vec<u8> = (0..ENTROPY_BYTES)
        .map(|i| ((7 * i + 3) % 256) as u8)
        .collect();
    let h = Poseidon::new(POOL_LOG_ROUNDS, [Fp::ZERO; RATE]);
    /*
     * The 37-word set pays the fee to `address(1)`, "whoever submits", which
     * is what a wallet sends when a lander or a searcher lands the proof.
     */
    let submitter = if cfg!(feature = "not_before") {
        "0x0000000000000000000000000000000000000001"
    } else {
        "0x5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b"
    };
    let payee_pk = pack_u256(&derive(&h, secret(200)).spend_pk);
    let zero = "0x0000000000000000000000000000000000000000";

    #[cfg(not(feature = "not_before"))]
    let cases = [
        Case {
            name: "transfer-eth",
            asset: 0,
            input: 2_000_000_000_000_000,
            public_amount: 0,
            fee: 100_000_000_000_000,
            outputs: [2_000_000_000_000_000, 1_900_000_000_000_000],
            to_payee: true,
            recipient: zero,
            clearing_price: 0,
        },
        Case {
            name: "withdraw-eth",
            asset: 0,
            input: 2_000_000_000_000_000,
            public_amount: 2_000_000_000_000_000,
            fee: 100_000_000_000_000,
            outputs: [1_900_000_000_000_000, 0],
            to_payee: false,
            recipient: "0x8ba1f109551bd432803012645ac136ddd64dba72",
            clearing_price: 1_000_000,
        },
        // Fee at 0.5% of the withdrawn amount, the most the pool takes on a
        // withdrawal, so the pool settles it end to end.
        Case {
            name: "withdraw-capped",
            asset: 0,
            input: 2_000_000_000_000_000,
            public_amount: 2_000_000_000_000_000,
            fee: 10_000_000_000_000,
            outputs: [1_990_000_000_000_000, 0],
            to_payee: false,
            recipient: "0x8ba1f109551bd432803012645ac136ddd64dba72",
            clearing_price: 1_000_000,
        },
        Case {
            name: "transfer-nox",
            asset: 1,
            input: 5_000_000,
            public_amount: 0,
            fee: 100_000,
            outputs: [5_000_000, 4_900_000],
            to_payee: true,
            recipient: zero,
            clearing_price: 0,
        },
    ];

    /*
     * The 37-word statement, at the fees the production pool's policy accepts
     * from a relayed proof: the protocol part (a flat fee for a transfer, 0.5%
     * of the amount for a withdrawal) plus the lowest gas rung. Public amounts
     * are standard sizes of each asset's range, ETH 10^16 to 10^19 wei and NOX
     * 10^12 to 10^15 units, so the pool takes every one of these as it stands.
     * Each was checked with the policy's `settlementFee(asset, amount, fee,
     * true)` before it was pinned.
     */
    #[cfg(feature = "not_before")]
    let cases = [
        Case {
            name: "transfer-eth",
            asset: 0,
            input: 10_000_000_000_000_000,
            public_amount: 0,
            fee: 3_000_000_000_000_000,
            outputs: [10_000_000_000_000_000, 7_000_000_000_000_000],
            to_payee: true,
            recipient: zero,
            clearing_price: 0,
        },
        Case {
            name: "withdraw-eth",
            asset: 0,
            input: 10_000_000_000_000_000,
            public_amount: 10_000_000_000_000_000,
            fee: 2_550_000_000_000_000,
            outputs: [7_450_000_000_000_000, 0],
            to_payee: false,
            recipient: "0x8ba1f109551bd432803012645ac136ddd64dba72",
            clearing_price: 1_000_000,
        },
        Case {
            name: "transfer-nox",
            asset: 1,
            input: 10_000_000_000_000,
            public_amount: 0,
            fee: 2_400_000_000_000,
            outputs: [10_000_000_000_000, 7_600_000_000_000],
            to_payee: true,
            recipient: zero,
            clearing_price: 0,
        },
        Case {
            name: "withdraw-nox",
            asset: 1,
            input: 10_000_000_000_000,
            public_amount: 10_000_000_000_000,
            fee: 2_050_000_000_000,
            outputs: [7_950_000_000_000, 0],
            to_payee: false,
            recipient: "0x8ba1f109551bd432803012645ac136ddd64dba72",
            clearing_price: 1_000_000,
        },
    ];

    let mut ok = true;
    let mut index = Vec::new();
    for c in &cases {
        // One wallet, one secret, two notes: what a wallet spends, and what the
        // Zig client models.
        let sks = [secret(101), secret(101)];
        let notes = [owned(sks[0], 11, c.input), owned(sks[1], 12, c.input)].map(|mut n| {
            n.asset_id = c.asset;
            n
        });
        let cms: Vec<String> = notes.iter().map(|n| pack_u256(&note_parts(n).cm)).collect();
        let mut tree = PoolTree::with_depth(h.clone(), TREE_DEPTH);
        for n in &notes {
            tree.insert(note_parts(n).cm);
        }
        let root = pack_u256(&tree.root());
        let spend_pk = if c.to_payee {
            format!("[\"{payee_pk}\", \"self\"]")
        } else {
            "[\"self\", \"self\"]".into()
        };
        let request = format!(
            "{{\n  \"asset_id\": {},\n  \"pool_leaves\": [\"{}\", \"{}\"],\n  \"assoc_leaves\": [\"{}\", \"{}\"],\n  \
             \"input_pool_index\": [0, 1],\n  \"input_assoc_index\": [0, 1],\n  \"note_root\": \"{root}\",\n  \
             \"assoc_root\": \"{root}\",\n  \"recipient\": \"{}\",\n  \"fee_recipient\": \"{submitter}\",\n  \
             \"clearing_price\": {},\n  \"public_amount\": {},\n  \"fee\": {},\n  \"output_values\": [{}, {}],\n  \
             \"output_spend_pk\": {spend_pk}\n}}\n",
            c.asset, cms[0], cms[1], cms[0], cms[1], c.recipient, c.clearing_price, c.public_amount, c.fee, c.outputs[0], c.outputs[1]
        );
        // Word 36: every vector in the 37-word set proves at one grid time.
        let request = if cfg!(feature = "not_before") {
            request.replacen('{', "{\n  \"not_before\": 1790000400,", 1)
        } else {
            request
        };
        let limbs = |sk: &[Fp; RATE]| {
            format!(
                "[{}]",
                sk.iter()
                    .map(|v| v.to_u64().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        let seed = format!(
            "{{\n  \"artifact\": \"live-seed\",\n  \"warning\": \"fixture secrets for a test vector; they spend nothing\",\n  \
             \"secrets\": [{}, {}],\n  \"notes\": [{}, {}]\n}}\n",
            limbs(&sks[0]),
            limbs(&sks[1]),
            note_json(&notes[0]),
            note_json(&notes[1])
        );
        let dir = format!("{out}/{}", c.name);
        let write = |f: &str, body: &[u8]| {
            std::fs::create_dir_all(&dir)
                .and_then(|_| std::fs::write(format!("{dir}/{f}"), body))
                .unwrap_or_else(|e| {
                    eprintln!("cannot write {dir}/{f}: {e}");
                    std::process::exit(2)
                })
        };
        write("request.json", request.as_bytes());
        write("seed.json", seed.as_bytes());
        write("entropy.hex", hex(&entropy).as_bytes());

        let t = std::time::Instant::now();
        let opts = Options {
            cache: Some(&cache),
            ..Default::default()
        };
        match prove_with(&request, &seed, &entropy, &opts) {
            Ok((proof, publics)) => {
                let digest = hex(&keccak256(&proof.bytes));
                let v = verify(&proof.bytes, &publics, &cache);
                let r = zk_fri_rank_check(&proof.bytes, &publics);
                println!(
                    "{:<13} {} bytes in {:?}, keccak256 {}, verify {:?}, rank {:?}",
                    c.name,
                    proof.bytes.len(),
                    t.elapsed(),
                    &digest[..16],
                    v.is_ok(),
                    r.is_ok()
                );
                ok &= v.is_ok() && r.is_ok();
                write("proof.bin", &proof.bytes);
                write("proof.json", to_json(&proof).as_bytes());
                let words: Vec<String> = publics.iter().map(u64::to_string).collect();
                write(
                    "publics.json",
                    format!("{{\n  \"publics\": [{}],\n  \"proof_keccak256\": \"{digest}\",\n  \"proof_bytes\": {}\n}}\n", words.join(", "), proof.bytes.len())
                        .as_bytes(),
                );
                index.push(format!(
                    "    {{\"name\": \"{}\", \"proof_keccak256\": \"{digest}\"}}",
                    c.name
                ));
            }
            Err(e) => {
                println!("{:<13} refused: {e}", c.name);
                ok = false;
            }
        }
    }
    let idx = format!(
        "{{\n  \"artifact\": \"wallet-vectors\",\n  \"vectors\": [\n{}\n  ]\n}}\n",
        index.join(",\n")
    );
    std::fs::write(format!("{out}/index.json"), idx).unwrap_or_else(|e| {
        eprintln!("cannot write the index: {e}");
        std::process::exit(2)
    });
    if !ok {
        std::process::exit(1);
    }
}
