// NONOS Operating System (AGPL-3.0-or-later)
//! A settlement proof against the root a live pool published, in one process.
//!
//! `emit_recursion_pre` proves the settlement outer over a spend that plants
//! its own tree, so its statement is true of a pool nobody runs. This proves
//! the same outer over a spend of notes that are actually in a deployed pool,
//! opened against the root that pool published, which is the difference
//! between a fixture and a payment.
//!
//!     prove_settlement_published <request.json> <live-seed.json> <out.proof> [root=<hex>] [point=<name>]
//!
//! The request and the seed file are what `host::build_spend` reads, and it
//! refuses a request that does not describe the pool before a minute of
//! proving is spent on a statement the pool would reject. The two created
//! notes are owned by fresh secrets written to a private file beside the
//! proof, so the value this spend moves is spendable afterwards.
//!
//! This is the path where one machine holds the secrets and makes the outer.
//! `prove_inner` and `relay_settlement` are the same proof split at the
//! inner, for a wallet that proves and a relayer that folds.

use stark_proofs::host::{build_spend, die, point_from_args, prove_outer, read_text};
use stark_proofs::recursion_assembly::inner::{self, shield_join_split_of};
use stark_proofs::recursion_assembly::point::Point;
use stark_proofs::recursion_assembly::{assemble_over_wired, Tamper};
use stark_proofs::shield_params::inner as inner_point;
use stark_proofs::crypto::stark::air::RATE;
use stark_proofs::crypto::stark::field::Fp;
use stark_proofs::host::os_words;
use std::time::Instant;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let [req_path, seed_path, out] = [a.first(), a.get(1), a.get(2)].map(|x| {
        x.cloned().unwrap_or_else(|| {
            die("usage: prove_settlement_published <request.json> <live-seed.json> <out.proof> [root=<hex>]")
        })
    });
    let expected_root = a.iter().find_map(|s| s.strip_prefix("root=")).map(str::to_string);

    if inner::extra() != inner_point::EXTRA_BLOWUP_BITS {
        die("the inner must prove at the deployment blowup; NONOS_INNER_EXTRA is set and it is refused here");
    }
    assert!(
        Point::emit_rounds(),
        "a one round prover would contradict the layout a verifier was generated from"
    );

    let t0 = Instant::now();
    let built = build_spend(
        &read_text(&req_path),
        &read_text(&seed_path),
        &seed_path,
        &format!("{out}.outputs.json"),
    );
    println!("inner     join-split against the published roots built in {:?}", t0.elapsed());

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
