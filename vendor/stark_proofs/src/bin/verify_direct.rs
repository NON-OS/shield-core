// NONOS Operating System (AGPL-3.0-or-later)
//! Verify a spend proved directly for the chain, against the words a verifier
//! is handed rather than the ones it was proved under.
//!
//!     verify_direct <proof> <publics.json> q=<queries> grind=<bits> extra=<bits>
//!
//! The circuit is rebuilt from the words, as the chain's program is fixed and
//! reads the words from calldata. Exits 0 when the proof verifies, 1 when it is
//! refused, and prints why.

use stark_proofs::crypto::stark::air::{periodic_root, stark_verify_ext_rounds_why};
use stark_proofs::crypto::stark::field::Fp;
use stark_proofs::host::{die, read_text, Json};
use stark_proofs::proof_wire::{deserialize_rounds, ParamSet};
use stark_proofs::shield::join::join_split_shape;
use stark_proofs::shield::member::TREE_DEPTH;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (Some(proof_path), Some(pub_path)) = (a.first(), a.get(1)) else {
        die("usage: verify_direct <proof> <publics.json> q= grind= extra=")
    };
    let num = |key: &str| -> u64 {
        a.iter()
            .find_map(|s| s.strip_prefix(key))
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| die(&format!("missing {key}<n>")))
    };
    let (q, grind, extra) = (num("q=") as usize, num("grind=") as u32, num("extra=") as u32);
    let words: Vec<Fp> = Json(&read_text(pub_path)).u64s("publics").into_iter().map(Fp::from_u64).collect();
    let air = join_split_shape(TREE_DEPTH, &words);
    let params = ParamSet::of(&air, q, grind, extra);
    let bytes = std::fs::read(proof_path).unwrap_or_else(|e| die(&format!("cannot read {proof_path}: {e}")));
    let Some(rounds) = deserialize_rounds(&bytes, &params) else {
        println!("REFUSED   {proof_path}: not a proof at this point for this circuit");
        std::process::exit(1)
    };
    let root = periodic_root(&air, extra);
    match stark_verify_ext_rounds_why(air, &rounds, q, grind, extra, &root, &words) {
        Ok(()) => println!("VERIFIED  {proof_path} against {pub_path}, periodic root {}", hex(&root)),
        Err(why) => {
            println!("REFUSED   {proof_path} against {pub_path}: {why}");
            std::process::exit(1)
        }
    }
}

fn hex(r: &[u8; 32]) -> String {
    r[..24].iter().map(|b| format!("{b:02x}")).collect()
}
