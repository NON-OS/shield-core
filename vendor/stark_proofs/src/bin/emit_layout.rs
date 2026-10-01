// NONOS Operating System (AGPL-3.0-or-later)
//! Emit the proof layout, as JSON for tooling or as Solidity for the chain,
//! so a verifier generator reads numbers rather than a person transcribing
//! them.
//!
//! The Yul should hold literal constants: a literal is free and a computed
//! offset is not. What must not happen is a literal arriving by hand. Twice
//! on 2026-09-22 a number reached an offset table by being typed, and both
//! times it was wrong in a way that would have compiled cleanly and read the
//! wrong bytes.
//!
//! So the constants come from here, and the emitted library recomputes the
//! geometry hash from the constants it actually compiled in. A hand edit to
//! the generated file changes the digest and the build stops.
//!
//!     cargo run --release --bin emit_layout                 > layout.json
//!     cargo run --release --bin emit_layout -- --solidity   > ProofLayout.sol

use stark_proofs::proof_wire::{Layout, ParamSet, LAYOUT_DOMAIN};

fn arg(name: &str, default: u32) -> u32 {
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        if a == name {
            return it
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| panic!("{name} wants a number"));
        }
    }
    default
}

fn flag(name: &str) -> bool {
    std::env::args().skip(1).any(|a| a == name)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn json(l: &Layout) {
    let m = l.manifest();
    println!("{{");
    println!("  \"params_id\": \"{}\",", hex(&m.params_id));
    println!("  \"layout_id\": \"{}\",", hex(&l.id()));
    for (name, v) in l.words() {
        println!("  \"{}\": {},", name.to_lowercase(), v);
    }
    println!("  \"fri_layers\": [");
    for (i, f) in m.fri_layers.iter().enumerate() {
        let comma = if i + 1 == m.fri_layers.len() { "" } else { "," };
        println!(
            "    {{ \"base\": {}, \"stride\": {}, \"depth\": {}, \"count\": {} }}{comma}",
            f.base, f.stride, f.depth, f.count
        );
    }
    println!("  ]");
    println!("}}");
}

fn solidity(l: &Layout) {
    let words = l.words();
    let domain = core::str::from_utf8(LAYOUT_DOMAIN).expect("the domain tag is text");

    println!("// SPDX-License-Identifier: AGPL-3.0-or-later");
    println!("// Written by `cargo run --bin emit_layout -- --solidity`. Edits here fail the build.");
    println!("//");
    println!("// Every constant below is derived from the proof parameters by");
    println!("// stark_proofs::proof_wire::layout and is the same arithmetic the Rust");
    println!("// serializer and strict parser use. LAYOUT_ID is a hash over all of them;");
    println!("// layoutId() recomputes it from what this file actually compiled in, so a");
    println!("// hand edit here fails the build instead of reading the wrong bytes.");
    println!("pragma solidity ^0.8.24;");
    println!();
    println!("library ProofLayout {{");
    println!("    bytes32 internal constant PARAMS_ID =");
    println!("        0x{};", hex(&l.params_id));
    println!("    bytes32 internal constant LAYOUT_ID =");
    println!("        0x{};", hex(&l.id()));
    println!();
    let w = words.iter().map(|(n, _)| n.len()).max().unwrap_or(0);
    for (name, v) in &words {
        println!("    uint64 internal constant {name:<w$} = {v};");
    }
    println!();
    println!("    /// The geometry hash, recomputed from this file's own constants.");
    println!("    /// abi.encodePacked writes a uint64 as eight big endian bytes and a");
    println!("    /// string literal as its bytes with no length prefix, which is exactly");
    println!("    /// the preimage the Rust side hashes.");
    println!("    function layoutId() internal pure returns (bytes32) {{");
    println!("        return keccak256(");
    println!("            abi.encodePacked(");
    println!("                \"{domain}\",");
    println!("                PARAMS_ID,");
    for (i, (name, _)) in words.iter().enumerate() {
        let comma = if i + 1 == words.len() { "" } else { "," };
        println!("                {name}{comma}");
    }
    println!("            )");
    println!("        );");
    println!("    }}");
    println!();
    println!("    /// Wire this into deployment or a test. It is the whole point of the");
    println!("    /// file: two implementations of one geometry, proving they agree.");
    println!("    function selfCheck() internal pure {{");
    println!("        require(layoutId() == LAYOUT_ID, \"ProofLayout: constants edited\");");
    println!("    }}");
    println!();
    println!("    /// Byte offset of query i inside each repeated section.");
    println!("    function friQuery(uint256 i) internal pure returns (uint256) {{");
    println!("        return FRI_BASE + 4 + i * FRI_STRIDE;");
    println!("    }}");
    println!();
    println!("    function consQuery(uint256 i) internal pure returns (uint256) {{");
    println!("        return CONS_BASE + 4 + i * CONS_STRIDE;");
    println!("    }}");
    println!();
    println!("    function sidecarQuery(uint256 i) internal pure returns (uint256) {{");
    println!("        return SIDECAR_BASE + 4 + 16 * N_PERIODIC + i * SIDECAR_STRIDE;");
    println!("    }}");
    println!();
    println!("    function permQuery(uint256 i) internal pure returns (uint256) {{");
    println!("        return PERM_BASE + i * PERM_STRIDE;");
    println!("    }}");
    println!("}}");
}

fn main() {
    /*
     * The defaults are the shipped settlement point, so the tool with no
     * arguments emits the geometry of the artifact every other check in the
     * repository is anchored to.
     */
    let params = ParamSet {
        n_queries: arg("--queries", 12),
        grind_bits: arg("--grind-bits", 32),
        extra_blowup_bits: arg("--extra-blowup-bits", 7),
        fri_fold_log: arg("--fri-fold-log", 2),
        fri_stop_log: arg("--fri-stop-log", 8),
        digest_bytes: arg("--digest-bytes", 24),
        trace_width: arg("--trace-width", 41),
        n_periodic: arg("--n-periodic", 119),
        log_trace_len: arg("--log-trace-len", 18),
        constraint_degree: arg("--constraint-degree", 8),
        window_size: arg("--window-size", 2),
        num_transition: arg("--num-transition", 37),
        n_boundary: arg("--n-boundary", 723),
        coset_shift: arg("--coset-shift", 7) as u64,
        commit_grind_bits: 0,
        grind_chunks: 1,
    };

    let l = Layout::of(&params);
    if flag("--solidity") {
        solidity(&l);
    } else {
        json(&l);
    }
}
