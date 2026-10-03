// NONOS Operating System (AGPL-3.0-or-later)
//! Pinned activity proofs: claims of one, two and four spends by one fixture
//! key against a fixture week, proved at shape A from fixed entropy, so the
//! bytes are the same on every run.
//!
//!     emit_activity <out-dir>
//!
//! Each claim's directory holds `proof.bin` (format 7), `proof.f5` (the same
//! proof per query, what the program-image emitters read), `publics.json`
//! (the eighteen words) and `statement.json`. `week.json` holds the week's
//! leaves and Λ_e as decimal strings. The key, the notes and the other spends
//! are fixtures and spend nothing. A manifest lists every proof's keccak256
//! and the circuit's parameter id and periodic root.

use stark_proofs::activity::{
    key_commitment, nullifier, params, prove_both, shape, tag, Slot, Statement, Witness, DEPTH,
    EXTRA_BLOWUP_BITS, LOG_ROUNDS, SLOTS,
};
use stark_proofs::crypto::stark::air::{periodic_root, Poseidon, RATE};
use stark_proofs::crypto::stark::field::Fp;
use stark_proofs::crypto::stark::hash::keccak256;
use stark_proofs::host::{die, pack_u256};
use stark_proofs::shield::member::PoolTree;
use std::fmt::Write as _;

const WEEK: u64 = 2_934;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn f4(v: [u64; RATE]) -> [Fp; RATE] {
    v.map(Fp::from_u64)
}

fn main() {
    let Some(out) = std::env::args().nth(1) else {
        die("usage: emit_activity <out-dir>")
    };
    let h = Poseidon::new(LOG_ROUNDS, [Fp::ZERO; RATE]);
    let nk = f4([0x1111, 0x2222, 0x3333, 0x4444]);
    let payout = f4([11, 12, 13, 14]);
    let note = |i: u64| (f4([100 + i, 200 + i, 300 + i, 400 + i]), 1_000 + 7 * i);

    /*
     * The week: other spends between the key's, so the claimed positions are
     * not adjacent and the gaps are not all zero.
     */
    let mut tree = PoolTree::with_depth(h, DEPTH);
    let mut mine = Vec::new();
    for i in 0..5u64 {
        tree.insert(f4([9_000 + i, 1, 2, 3]));
        let (cm, pos) = note(i);
        mine.push((i, tree.insert(nullifier(nk, cm, pos))));
    }
    let lambda = tree.root();

    let quad = |q: &[Fp; RATE]| {
        format!(
            "[{}]",
            q.iter()
                .map(|v| format!("\"{}\"", v.to_u64()))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let week_leaves: Vec<[Fp; RATE]> = (0..5u64)
        .flat_map(|i| {
            let (cm, pos) = note(i);
            [f4([9_000 + i, 1, 2, 3]), nullifier(nk, cm, pos)]
        })
        .collect();
    let week = format!(
        "{{\n  \"depth\": {DEPTH},\n  \"week\": {WEEK},\n  \"lambda\": {},\n  \"leaves\": [\n    {}\n  ]\n}}\n",
        quad(&lambda),
        week_leaves.iter().map(quad).collect::<Vec<_>>().join(",\n    ")
    );
    std::fs::create_dir_all(&out)
        .and_then(|_| std::fs::write(format!("{out}/week.json"), week))
        .unwrap_or_else(|e| die(&format!("{out}/week.json: {e}")));

    let entropy: Vec<u8> = (0..512).map(|i| ((7 * i + 3) % 256) as u8).collect();
    let mut manifest = String::from(
        "# Activity pinned proofs\n\nClaims by one fixture key against a fixture week, at 19 queries and a 28-bit grind, from the fixed entropy `(7 i + 3) mod 256`. Each proof was verified from its format 7 bytes and carries its rank certificate.\n\n| claim | k | leaves | bytes | keccak256 |\n|---|---|---|---|---|\n",
    );
    let claims: [(&str, &[usize]); 3] = [("k1", &[2]), ("k2", &[0, 3]), ("k4", &[0, 1, 3, 4])];
    let mut first: Option<Statement> = None;
    for (name, which) in claims {
        let mut slots: [Option<Slot>; SLOTS] = Default::default();
        for (j, &m) in which.iter().enumerate() {
            let (i, at) = mine[m];
            let (cm, note_position) = note(i);
            let (siblings, right) = tree.path(at);
            slots[j] = Some(Slot {
                cm,
                note_position,
                siblings,
                right,
            });
        }
        let w = Witness { nk, slots };
        let st = Statement::new(
            lambda,
            WEEK,
            which.len() as u64,
            tag(nk, WEEK),
            payout,
            key_commitment(nk),
        )
        .unwrap_or_else(|| die("a count of 1 to 4"));
        let t = std::time::Instant::now();
        let (f7, f5) =
            prove_both(&st, &w, &entropy).unwrap_or_else(|e| die(&format!("{name}: {e:?}")));
        println!(
            "{name} {} bytes in {:.1} s",
            f7.len(),
            t.elapsed().as_secs_f64()
        );

        let dir = format!("{out}/{name}");
        let words: Vec<String> = st.words().iter().map(|v| v.to_u64().to_string()).collect();
        let write = |f: &str, body: &[u8]| {
            std::fs::create_dir_all(&dir)
                .and_then(|_| std::fs::write(format!("{dir}/{f}"), body))
                .unwrap_or_else(|e| die(&format!("{dir}/{f}: {e}")))
        };
        let publics = format!("{{\"publics\": [{}]}}\n", words.join(", "));
        write("proof.bin", &f7);
        write("proof.f5", &f5);
        write("proof.f5.publics.json", publics.as_bytes());
        write("publics.json", publics.as_bytes());
        let at: Vec<String> = which.iter().map(|&m| mine[m].1.to_string()).collect();
        write(
            "statement.json",
            format!(
                "{{\n  \"lambda\": \"{}\",\n  \"week\": {WEEK},\n  \"count\": {},\n  \"tag\": \"{}\",\n  \"payout\": \"{}\",\n  \"key\": \"{}\",\n  \"leaves\": [{}]\n}}\n",
                pack_u256(&lambda),
                which.len(),
                pack_u256(&st.tag),
                pack_u256(&payout),
                pack_u256(&st.key),
                at.join(", ")
            )
            .as_bytes(),
        );
        let _ = writeln!(
            manifest,
            "| {name} | {} | {} | {} | `{}` |",
            which.len(),
            at.join(", "),
            f7.len(),
            hex(&keccak256(&f7))
        );
        first.get_or_insert(st);
    }
    let st = first.unwrap_or_else(|| die("no claim"));
    let air = shape(&st.words()).unwrap_or_else(|| die("the shape"));
    let pid = params(&st).unwrap_or_else(|e| die(&format!("{e:?}"))).id();
    let _ = write!(
        manifest,
        "\nΛ_e: `{}`\n\nParameter id: `{}`\n\nPeriodic root: `{}`\n",
        pack_u256(&lambda),
        hex(&pid),
        hex(&periodic_root(&air, EXTRA_BLOWUP_BITS))
    );
    std::fs::write(format!("{out}/MANIFEST.md"), manifest)
        .unwrap_or_else(|e| die(&format!("manifest: {e}")));
}
