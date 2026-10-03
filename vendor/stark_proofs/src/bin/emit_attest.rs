// NONOS Operating System (AGPL-3.0-or-later)
//! Pinned attestation proofs: one kernel, one capsule and one bootloader slot
//! of a fixture 256-slot tree, proved at the attestation point from fixed
//! entropy, so the bytes are the same on every run.
//!
//!     emit_attest <out-dir>
//!
//! Each slot's directory holds `proof.bin` (format 7, what a gate reads),
//! `proof.f5` (the same proof per query, what the program-image emitters
//! read), `publics.json` (the nine words) and `statement.json` (root, digest,
//! kind, slot). `tree.json` holds every leaf and the root as decimal
//! strings. The contexts are fixtures: their digests come from a public rule
//! and stand for no real binary. A manifest lists every proof's keccak256
//! and the circuit's parameter id and periodic root.

use stark_proofs::attest::{
    leaf, params, prove_both, shape, Statement, Witness, DEPTH, EXTRA_BLOWUP_BITS, KIND_BOOTLOADER,
    KIND_CAPSULE, KIND_KERNEL, KIND_PAD, POINTS,
};
use stark_proofs::crypto::stark::air::{periodic_root, Poseidon, RATE};
use stark_proofs::crypto::stark::field::Fp;
use stark_proofs::crypto::stark::hash::keccak256;
use stark_proofs::host::{die, pack_u256};
use std::fmt::Write as _;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A fixture context digest: keccak256 of a label, never a real measurement.
fn digest(label: &str) -> [u8; 32] {
    keccak256(label.as_bytes())
}

fn main() {
    let Some(out) = std::env::args().nth(1) else {
        die("usage: emit_attest <out-dir>")
    };
    let h = Poseidon::new(stark_proofs::attest::LOG_ROUNDS, [Fp::ZERO; RATE]);
    let slots = [
        ("kernel", 3usize, KIND_KERNEL),
        ("capsule", 77, KIND_CAPSULE),
        ("bootloader", 200, KIND_BOOTLOADER),
    ];
    let leaves: Vec<[Fp; RATE]> = (0..1usize << DEPTH)
        .map(|i| match slots.iter().find(|s| s.1 == i) {
            Some((name, _, kind)) => leaf(*kind, &digest(&format!("fixture {name}"))),
            None => leaf(KIND_PAD, &digest(&format!("fixture pad {i}"))),
        })
        .collect();
    let mut levels = vec![leaves];
    while levels.last().map_or(0, Vec::len) > 1 {
        let up = levels
            .last()
            .map(|l| l.chunks(2).map(|p| h.compress(&p[0], &p[1])).collect())
            .unwrap_or_default();
        levels.push(up);
    }
    let root = levels[DEPTH][0];

    /*
     * The whole leaf set and the root, every word a decimal string: what an
     * enrollment index publishes and what a page refolds. Strings, because a
     * word runs to 2^64 and a JSON number read by a browser keeps 53 bits.
     */
    let quad = |q: &[Fp; RATE]| {
        format!(
            "[{}]",
            q.iter()
                .map(|v| format!("\"{}\"", v.to_u64()))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let tree = format!(
        "{{\n  \"depth\": {DEPTH},\n  \"root\": {},\n  \"leaves\": [\n    {}\n  ]\n}}\n",
        quad(&root),
        levels[0]
            .iter()
            .map(quad)
            .collect::<Vec<_>>()
            .join(",\n    ")
    );
    std::fs::create_dir_all(&out)
        .and_then(|_| std::fs::write(format!("{out}/tree.json"), tree))
        .unwrap_or_else(|e| die(&format!("{out}/tree.json: {e}")));
    let entropy: Vec<u8> = (0..512).map(|i| ((7 * i + 3) % 256) as u8).collect();
    let point = POINTS[0];

    let mut manifest = String::from(
        "# Attestation pinned proofs\n\nOne slot per kind of a fixture 256-slot tree, at 26 queries and a 28-bit grind, from the fixed entropy `(7 i + 3) mod 256`. Each proof was verified from its format 7 bytes and carries its rank certificate.\n\n| slot | kind | index | bytes | keccak256 |\n|---|---|---|---|---|\n",
    );
    let mut first: Option<Statement> = None;
    for (name, index, kind) in slots {
        let st = Statement::new(root, digest(&format!("fixture {name}")), kind)
            .unwrap_or_else(|| die("a provable kind"));
        let (mut siblings, mut right, mut i) = (Vec::new(), Vec::new(), index);
        for level in &levels[..DEPTH] {
            siblings.push(level[i ^ 1]);
            right.push(i & 1 == 1);
            i >>= 1;
        }
        let w = Witness { siblings, right };
        let t = std::time::Instant::now();
        let (f7, f5) =
            prove_both(&st, &w, &entropy, point).unwrap_or_else(|e| die(&format!("{name}: {e:?}")));
        println!(
            "{name:<11} {} bytes in {:.1} s",
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
        write("proof.bin", &f7);
        write("proof.f5", &f5);
        write(
            "proof.f5.publics.json",
            format!("{{\"publics\": [{}]}}\n", words.join(", ")).as_bytes(),
        );
        write(
            "publics.json",
            format!("{{\"publics\": [{}]}}\n", words.join(", ")).as_bytes(),
        );
        write(
            "statement.json",
            format!(
                "{{\n  \"root\": \"{}\",\n  \"digest\": \"{}\",\n  \"kind\": {kind},\n  \"slot\": {index},\n  \"context\": \"fixture {name}\"\n}}\n",
                pack_u256(&root),
                hex(&st.digest)
            )
            .as_bytes(),
        );
        let _ = writeln!(
            manifest,
            "| {name} | {kind} | {index} | {} | `{}` |",
            f7.len(),
            hex(&keccak256(&f7))
        );
        first.get_or_insert(st);
    }
    let st = first.unwrap_or_else(|| die("no slot"));
    let air = shape(&st.words()).unwrap_or_else(|| die("the shape"));
    let pid = params(&st, point)
        .unwrap_or_else(|e| die(&format!("{e:?}")))
        .id();
    let _ = write!(
        manifest,
        "\nRoot: `{}`\n\nParameter id: `{}`\n\nPeriodic root: `{}`\n",
        pack_u256(&root),
        hex(&pid),
        hex(&periodic_root(&air, EXTRA_BLOWUP_BITS))
    );
    std::fs::write(format!("{out}/MANIFEST.md"), manifest)
        .unwrap_or_else(|e| die(&format!("manifest: {e}")));
}
