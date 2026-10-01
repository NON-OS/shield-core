// NONOS Operating System (AGPL-3.0-or-later)
//! The wallet's half of a relayed settlement: the inner proof, from the
//! secrets, and nothing else leaves the machine.
//!
//!     prove_inner <request.json> <live-seed.json> <out.inner>
//!
//! Same request and seed file as `prove_settlement_published`, same
//! refusals, same created notes written privately beside the output. What
//! differs is what comes out: the two round Poseidon proof of the join-split
//! on its own, hiding, at the inner's deployment point, and the thirty two
//! public words it absorbed. A relayer holding those two files makes the
//! outer with `relay_settlement`, and learns what the chain learns.
//!
//! The inner is a 24 column, 2^13 row circuit. Proving it is the part of a
//! settlement a device can do; the outer is the part it cannot, and this is
//! the seam between them.

use stark_proofs::crypto::stark::air::RATE;
use stark_proofs::crypto::stark::field::Fp;
use stark_proofs::host::{build_spend, die, os_words, pack_u256, read_text};
use stark_proofs::proof_wire::serialize_p_rounds;
use stark_proofs::recursion_assembly::inner::{self, hide, prove_raw, GRIND, NQ};
use stark_proofs::shield_params::inner as inner_point;
use std::time::Instant;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let [req_path, seed_path, out] = [a.first(), a.get(1), a.get(2)].map(|x| {
        x.cloned()
            .unwrap_or_else(|| die("usage: prove_inner <request.json> <live-seed.json> <out.inner>"))
    });
    if inner::extra() != inner_point::EXTRA_BLOWUP_BITS {
        die("the inner must prove at the deployment blowup; NONOS_INNER_EXTRA is set and it is refused here");
    }

    let t0 = Instant::now();
    let mut built = build_spend(
        &read_text(&req_path),
        &read_text(&seed_path),
        &seed_path,
        &format!("{out}.outputs.json"),
    );
    println!("inner     join-split against the published roots built in {:?}", t0.elapsed());

    let h = inner::hasher();
    let seed_words = os_words(RATE);
    let seed: [Fp; RATE] = core::array::from_fn(|i| seed_words[i]);
    let blind = hide(&h, &mut built.js, &seed, NQ);
    let t1 = Instant::now();
    let proved = prove_raw(&h, built.js, NQ, GRIND, inner::extra(), &blind);
    println!(
        "inner     proved hiding in {:?}, {} queries, grind {}, extra blowup {}",
        t1.elapsed(),
        NQ,
        GRIND,
        inner::extra()
    );

    let bytes = serialize_p_rounds(&proved.proof);
    std::fs::write(&out, &bytes).unwrap_or_else(|e| die(&format!("cannot write {out}: {e}")));
    println!("wrote {} bytes to {out}", bytes.len());

    /*
     * The intent, beside the bytes: the relayer rebuilds the inner circuit
     * from these words and nothing else, and the periodic root it prints
     * here is what that rebuild must land on.
     */
    let words: Vec<String> = proved.publics.iter().map(|v| v.to_u64().to_string()).collect();
    let intent_out = format!("{out}.intent.json");
    std::fs::write(
        &intent_out,
        format!(
            "{{\n  \"artifact\": \"{out}\",\n  \"note_root\": \"{}\",\n  \"assoc_root\": \"{}\",\n  \
             \"inner_periodic_root\": \"{}\",\n  \"n_publics\": {},\n  \"publics\": [{}]\n}}\n",
            pack_u256(&built.note_root),
            pack_u256(&built.assoc_root),
            pack_u256(&proved.root),
            proved.publics.len(),
            words.join(", ")
        ),
    )
    .unwrap_or_else(|e| die(&format!("cannot write {intent_out}: {e}")));
    println!("wrote {} public words to {intent_out}", proved.publics.len());
}
