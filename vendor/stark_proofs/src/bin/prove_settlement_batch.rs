// NONOS Operating System (AGPL-3.0-or-later)
//! Several spends under one settlement proof.
//!
//!     prove_settlement_batch <out.proof> [root=<hex>] [point=<name>] <request.json> <seed.json> [<request.json> <seed.json> ...]
//!
//! Each request and seed pair is what `prove_settlement_published` takes,
//! refused on its own terms, and the pairs are stacked into one join-split
//! in the order given: the publics are the intents' thirty two words end to
//! end, which is the layout the pool settles a batch by. One outer is proved
//! over the whole, so the operator's proof cost is paid once for every spend
//! in it. Each spend's created notes go to `<out.proof>.outputs-<i>.json`.
//!
//! What grows with the batch is measured, not modelled:
//! `batch_shape_tests::print_the_outer_shape_by_batch_size`.

use stark_proofs::crypto::stark::air::RATE;
use stark_proofs::crypto::stark::field::Fp;
use stark_proofs::host::{build_batch, die, os_words, point_from_args, prove_outer, read_text};
use stark_proofs::recursion_assembly::inner::{self, shield_join_split_of};
use stark_proofs::recursion_assembly::point::Point;
use stark_proofs::recursion_assembly::{assemble_over_wired, Tamper};
use stark_proofs::shield_params::inner as inner_point;
use std::time::Instant;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: prove_settlement_batch <out.proof> [root=<hex>] [point=<name>] <request.json> <seed.json> [...]";
    let out = a.first().cloned().unwrap_or_else(|| die(usage));
    let expected_root = a.iter().find_map(|s| s.strip_prefix("root=")).map(str::to_string);
    let pairs: Vec<&String> = a.iter().skip(1).filter(|s| !s.starts_with("root=") && !s.starts_with("point=")).collect();
    if pairs.is_empty() || !pairs.len().is_multiple_of(2) {
        die(usage);
    }
    if inner::extra() != inner_point::EXTRA_BLOWUP_BITS {
        die("the inner must prove at the deployment blowup; NONOS_INNER_EXTRA is set and it is refused here");
    }
    assert!(
        Point::emit_rounds(),
        "a one round prover would contradict the layout a verifier was generated from"
    );

    let items: Vec<(String, String, String, String)> = pairs
        .chunks(2)
        .enumerate()
        .map(|(i, p)| {
            (read_text(p[0]), read_text(p[1]), p[1].clone(), format!("{out}.outputs-{i}.json"))
        })
        .collect();
    let t0 = Instant::now();
    let built = build_batch(&items);
    println!(
        "batch     {} spends, {} public words, built against the published roots in {:?}",
        items.len(),
        built.js.intent.len(),
        t0.elapsed()
    );

    let rh = inner::hasher();
    let seed_words = os_words(RATE);
    let seed: [Fp; RATE] = core::array::from_fn(|i| seed_words[i]);
    let t1 = Instant::now();
    let inner_proof = shield_join_split_of(&rh, built.js, Some(&seed));
    println!("inner     proved hiding in {:?}", t1.elapsed());

    let t2 = Instant::now();
    let asm = assemble_over_wired(&rh, inner_proof, Tamper::None, usize::MAX, Point::emit_wiring());
    println!("assembled in {:?}", t2.elapsed());
    prove_outer(&rh, asm, &out, expected_root.as_deref(), point_from_args(&a));
}
