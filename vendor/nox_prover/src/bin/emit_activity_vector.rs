// NONOS Operating System (AGPL-3.0-or-later)
//! The wallet's activity vector: a request, a seed and entropy, and the answer
//! `nox_activity_prove` must give for them byte for byte.
//!
//!     emit_activity_vector <out-dir>
//!
//! The week holds eight other spends and three of the fixture key's, at
//! leaves 2, 5 and 6; the request names the three out of leaf order, so a
//! wallet that reproduces the answer also orders its slots as the circuit
//! requires. Fixture secrets: they spend nothing.

use nox_prover::activity::{prove_activity, to_json};
use stark_proofs::activity::{nullifier, DEPTH, LOG_ROUNDS};
use stark_proofs::crypto::stark::air::{Poseidon, RATE};
use stark_proofs::crypto::stark::field::Fp;
use stark_proofs::host::{die, pack_u256};
use stark_proofs::shield::key::derive;
use stark_proofs::shield::member::PoolTree;

const SK: [u64; RATE] = [0xa11ce, 0xb0b, 0xc0ffee, 0xd00d];
const WEEK: u64 = 2_935;
/// address(21 | 22 << 48 | 23 << 96 | 24 << 144), so P is [21, 22, 23, 24].
const PAYOUT: &str = "0x0018000000000017000000000016000000000015";

fn f4(v: [u64; RATE]) -> [Fp; RATE] {
    v.map(Fp::from_u64)
}

fn main() {
    let Some(out) = std::env::args().nth(1) else {
        die("usage: emit_activity_vector <out-dir>")
    };
    let h = Poseidon::new(LOG_ROUNDS, [Fp::ZERO; RATE]);
    let nk = derive(&h, f4(SK)).nk;
    let note = |i: u64| (f4([500 + i, 600 + i, 700 + i, 800 + i]), 4_000 + 11 * i);

    // Leaves: other spends, with the key's notes 0, 1 and 2 at leaves 2, 5 and 6.
    let mine = [(2usize, 0u64), (5, 1), (6, 2)];
    let mut leaves = Vec::new();
    let mut other = 0u64;
    for at in 0..11usize {
        match mine.iter().find(|m| m.0 == at) {
            Some(&(_, i)) => {
                let (cm, pos) = note(i);
                leaves.push(nullifier(nk, cm, pos));
            }
            None => {
                leaves.push(f4([77_000 + other, 3, 5, 7]));
                other += 1;
            }
        }
    }
    let mut tree = PoolTree::with_depth(h, DEPTH);
    for l in &leaves {
        tree.insert(*l);
    }
    let root = tree.root();

    let named = [2u64, 0, 1];
    let q = |s: String| format!("\"{s}\"");
    let request = format!(
        "{{\n  \"week\": {WEEK},\n  \"root\": {},\n  \"leaves\": [{}],\n  \"cms\": [{}],\n  \"note_positions\": [{}],\n  \"payout_address\": {}\n}}\n",
        q(pack_u256(&root)),
        leaves.iter().map(|l| q(pack_u256(l))).collect::<Vec<_>>().join(", "),
        named.iter().map(|&i| q(pack_u256(&note(i).0))).collect::<Vec<_>>().join(", "),
        named.iter().map(|&i| note(i).1.to_string()).collect::<Vec<_>>().join(", "),
        q(PAYOUT.into()),
    );
    let seed = format!(
        "{{\n  \"warning\": \"fixture secret for a test vector; it spends nothing\",\n  \"sk\": [{}]\n}}\n",
        SK.map(|v| v.to_string()).join(", ")
    );
    let entropy: Vec<u8> = (0..64u32).map(|i| (i * 13 + 5) as u8).collect();
    let (proof, publics) = prove_activity(&request, &seed, &entropy).unwrap_or_else(|e| die(&e));
    println!("activity vector: {} bytes, k = {}", proof.len(), publics[5]);

    let write = |f: &str, body: &[u8]| {
        std::fs::create_dir_all(&out)
            .and_then(|_| std::fs::write(format!("{out}/{f}"), body))
            .unwrap_or_else(|e| die(&format!("{out}/{f}: {e}")))
    };
    write("request.json", request.as_bytes());
    write("seed.json", seed.as_bytes());
    write(
        "entropy.hex",
        (entropy
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
            + "\n")
            .as_bytes(),
    );
    write("answer.json", (to_json(&proof, &publics) + "\n").as_bytes());
    write("proof.bin", &proof);
}
