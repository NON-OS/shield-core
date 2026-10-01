// NONOS Operating System (AGPL-3.0-or-later)
//! Writes spec/shield-key-hierarchy.json, the vector a wallet and a pool
//! derive against, and prints the two digests the pool hash is pinned to.
//!
//! Emitted rather than transcribed: a vector typed by hand agrees with the
//! circuit until the day it does not, and the note it describes is then
//! unspendable by everyone who implemented against it.

use stark_proofs::crypto::stark::air::{Poseidon, NOTE_LIMBS, RATE};
use stark_proofs::crypto::stark::field::Fp;
use stark_proofs::shield::key::{derive, nullifier, DEAD_DOMAIN, NULL_DOMAIN, SPEND_DOMAIN};
use stark_proofs::shield::note::{note_parts, Note, POOL_LOG_ROUNDS};

struct Case {
    seed: u64,
    value: u64,
    blinding: [u64; 4],
    leaf_index: u64,
}

const CASES: [Case; 3] = [
    Case { seed: 1, value: 1_000, blinding: [6, 7, 8, 9], leaf_index: 0 },
    Case { seed: 2, value: 5_000_000, blinding: [7, 8, 9, 10], leaf_index: 7 },
    Case { seed: 3, value: 4_294_967_295, blinding: [8, 9, 10, 11], leaf_index: 31 },
];

fn secret(seed: u64) -> [Fp; RATE] {
    core::array::from_fn(|i| Fp::from_u64(seed * 16 + i as u64 + 1))
}

fn list(d: &[Fp]) -> String {
    let v: Vec<String> = d.iter().map(|x| x.value().to_string()).collect();
    format!("[{}]", v.join(","))
}

fn main() {
    let h = Poseidon::new(POOL_LOG_ROUNDS, [Fp::ZERO; RATE]);
    let mut cases = Vec::new();
    for c in CASES.iter() {
        let sk = secret(c.seed);
        let k = derive(&h, sk);
        let note = Note {
            value: c.value,
            asset_id: 0,
            spend_pk: k.spend_pk.map(|v| v.value()),
            blinding: c.blinding,
        };
        let cm = note_parts(&note).cm;
        let nf = nullifier(&h, k.nk, cm, c.leaf_index, true);
        // The same note retired as a dummy would be. Emitted so a client that
        // hashes the live word for both inputs is caught by the vector rather
        // than by a pool that burns the wrong nullifier.
        let nf_dead = nullifier(&h, k.nk, cm, c.leaf_index, false);
        let owner = h.commit_owner(&k.spend_pk, &note.blinding.map(Fp::from_u64));
        cases.push(format!(
            "{{\"sk\":{},\"spend_pk\":{},\"nk\":{},\"value\":{},\"asset_id\":0,\
             \"blinding\":{},\"owner\":{},\"cm\":{},\"leaf_index\":{},\"nf\":{},\
             \"nf_dead\":{}}}",
            list(&sk),
            list(&k.spend_pk),
            list(&k.nk),
            c.value,
            list(&c.blinding.map(Fp::from_u64)),
            list(&owner),
            list(&cm),
            c.leaf_index,
            list(&nf),
            list(&nf_dead)
        ));
    }

    let json = format!(
        "{{\"artifact\":\"shield-key-hierarchy\",\"rounds\":{},\
         \"spend_domain\":{},\"null_domain\":{},\"dead_domain\":{},\
         \"derivation\":\"spend_pk=compress(sk,[SPEND_DOMAIN,0,0,0]); \
         nk=compress(sk,[NULL_DOMAIN,0,0,0]); \
         nf=compress(compress(nk,cm),[leaf_index,live?0:DEAD_DOMAIN,0,0])\",\
         \"commitment\":\"owner=compress(spend_pk,blinding); \
         cm=compress([value_lo,value_hi,asset_id,NOTE_DOMAIN],owner)\",\
         \"cases\":[{}]}}\n",
        1usize << POOL_LOG_ROUNDS,
        SPEND_DOMAIN,
        NULL_DOMAIN,
        DEAD_DOMAIN,
        cases.join(",")
    );

    let out = concat!(env!("CARGO_MANIFEST_DIR"), "/../spec/shield-key-hierarchy.json");
    std::fs::write(out, &json).expect("write vector");
    println!("wrote {out}");

    /*
     * The two pins the pool hash is gated on. They are separate on purpose:
     * one moves when the commitment layout moves, the other only when the
     * permutation itself does, so a change to the permutation cannot ride
     * in behind a change to the layout.
     */
    let mut limbs = [Fp::ZERO; NOTE_LIMBS];
    for (i, l) in limbs.iter_mut().enumerate() {
        *l = Fp::from_u64(i as u64 + 1);
    }
    let a: [Fp; RATE] = core::array::from_fn(|i| Fp::from_u64(i as u64 + 1));
    let b: [Fp; RATE] = core::array::from_fn(|i| Fp::from_u64(i as u64 + 5));
    println!("commit_note(1..=11) = {}", list(&h.commit_note(&limbs)));
    println!("compress(1..4, 5..8) = {}", list(&h.compress(&a, &b)));
}
