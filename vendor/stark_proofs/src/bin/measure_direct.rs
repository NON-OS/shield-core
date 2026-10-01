// NONOS Operating System (AGPL-3.0-or-later)
//! A spend proved directly for the chain: no outer, no recursion.
//!
//!     measure_direct <request.json> <live-seed.json> <out> q=<queries> grind=<bits> extra=<bits>
//!
//! The join-split is proved with the Keccak two round prover the on-chain
//! verifier replays, hiding (blinding at the radix-four count, the mask, the
//! copy constraint in `Fp2`), verified against its own periodic root, and
//! written in the format five codec. Prints the point's bits, the time, the
//! size and the size of each section, so a point is chosen from numbers.

use stark_proofs::crypto::stark::air::{stark_prove_ext_rounds, stark_verify_ext_rounds_why, Air};
use stark_proofs::crypto::stark::field::Fp;
use stark_proofs::crypto::stark::fri::FRI_FOLD_LOG;
use stark_proofs::host::{build_spend, die, os_words, read_text};
use stark_proofs::proof_wire::{serialize_rounds, Layout, ParamSet};
use stark_proofs::recursion_assembly::inner::{self, hide_at};
use stark_proofs::shield_params::{provable_bits, security_bits};
use std::time::Instant;

fn arg(a: &[String], key: &str) -> u64 {
    a.iter()
        .find_map(|s| s.strip_prefix(key))
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| die(&format!("missing {key}<n>")))
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let [req, seed, out] = [a.first(), a.get(1), a.get(2)]
        .map(|x| x.cloned().unwrap_or_else(|| die("usage: measure_direct <request> <seed> <out> q= grind= extra=")));
    let (q, grind, extra) = (arg(&a, "q=") as usize, arg(&a, "grind=") as u32, arg(&a, "extra=") as u32);
    println!(
        "point     {q} queries, grind {grind}, extra blowup {extra}: {} conjectured, {} provable bits",
        security_bits(q, grind, extra),
        provable_bits(q, grind, extra)
    );

    let mut built = build_spend(&read_text(&req), &read_text(&seed), &seed, &format!("{out}.outputs.json"));
    let h = inner::hasher();
    let words = os_words(4);
    let s: [Fp; 4] = core::array::from_fn(|i| words[i]);
    let blind = hide_at(&h, &mut built.js, &s, q, 1usize << FRI_FOLD_LOG);
    let js = built.js;
    println!(
        "shape     width {} log rows {} transitions {} boundaries {} periodic {} degree {}",
        js.wired.trace_width(),
        js.wired.log_trace_len(),
        js.wired.num_transition(),
        js.wired.boundary().len(),
        js.wired.periodic_columns().len(),
        js.wired.constraint_degree()
    );
    let params = ParamSet::of(&js.wired, q, grind, extra);
    let publics = js.intent.clone();
    let mut witness = js.witness;

    let t = Instant::now();
    let Some((rounds, tree, air)) =
        stark_prove_ext_rounds(js.wired, &mut witness, q, grind, extra, &publics, None, &blind)
    else {
        die("no proof")
    };
    println!("proved    in {:?}", t.elapsed());
    drop(witness);

    let root = tree.root();
    let t = Instant::now();
    let why = stark_verify_ext_rounds_why(air, &rounds, q, grind, extra, &root, &publics);
    println!("verified  in {:?}: {:?}", t.elapsed(), why);

    let bytes = serialize_rounds(&rounds, &params);
    std::fs::write(&out, &bytes).unwrap_or_else(|e| die(&format!("cannot write {out}: {e}")));
    let words: Vec<String> = publics.iter().map(|v| v.to_u64().to_string()).collect();
    std::fs::write(
        format!("{out}.publics.json"),
        format!(
            "{{\n  \"artifact\": \"{out}\",\n  \"point\": [{q}, {grind}, {extra}],\n  \"n_publics\": {},\n  \"publics\": [{}]\n}}\n",
            publics.len(),
            words.join(", ")
        ),
    )
    .unwrap_or_else(|e| die(&format!("cannot write the publics: {e}")));
    let l = Layout::of(&params);
    println!(
        "size      {} bytes: head {} fri {} cons {} sidecar {} perm {}, log domain {}, {} FRI layers, final {}",
        bytes.len(),
        l.fri.base,
        l.fri.end - l.fri.base,
        l.cons.end - l.cons.base,
        l.sidecar.end - l.sidecar.base,
        l.perm.end - l.perm.base,
        l.log_domain,
        l.fri_layers,
        l.n_final
    );
}
