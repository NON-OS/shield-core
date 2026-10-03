// NONOS Operating System (AGPL-3.0-or-later)
//! Write one genuine spend witness, the file `prove_from_witness` reads.
//!
//! Genuine means the openings are real paths in a real tree and the roots are
//! that tree's, so the spend it describes is one the circuit accepts. A
//! synthetic witness with invented paths walks to a root nobody published and
//! fails membership, which says nothing about the wire format and nothing about
//! the prover.
//!
//! It exists for two readers. `prove_from_witness` takes it and produces a
//! transfer proof, end to end. And a client writes the same spend in its own
//! code, so the two files can be compared word for word:
//! two languages, one layout, and a disagreement that is a diff rather than a
//! proof that will not parse.
//!
//!     emit_witness [out.wit]

use stark_proofs::crypto::stark::air::{Poseidon, RATE};
use stark_proofs::crypto::stark::field::Fp;
use stark_proofs::shield::join::{address_from_u64, address_limbs, Witnessed};
use stark_proofs::shield::member::{PoolTree, TREE_DEPTH};
use stark_proofs::shield::note::{note_parts, Note, POOL_LOG_ROUNDS};
use stark_proofs::shield::test::fixture::{owned, plain, secret};
use stark_proofs::shield::witness_wire::{write, SpendWitness};

/// The client's tree depth, because the point of this file is that a client
/// can write the same one and the two can be diffed. The client fixes its depth
/// at 32, so a witness at any other depth is a file the client cannot
/// produce and the comparison never happens.
///
/// It is also the deployed depth, so what this writes is the shape a real
/// wallet writes rather than a convenient small one.
const DEPTH: usize = TREE_DEPTH;

/// The pads the association set holds before the two spent notes, as the
/// planted set uses. Stated here because a client rebuilding this tree has to
/// place its leaves in the same order or it computes a different root.
const ASSOC_PADS: [u64; 3] = [900, 901, 902];

const PUBLIC_AMOUNT: u64 = 200;
const FEE: u64 = 100;
const CLEARING_PRICE: u64 = 1_000_000;
const RECIPIENT: u64 = 0xBEEF;
/// The submitter the fee pays: nonzero because the fee is.
const FEE_RECIPIENT: u64 = 0xFEE;

fn hasher() -> Poseidon {
    Poseidon::new(POOL_LOG_ROUNDS, [Fp::ZERO; RATE])
}

fn pad(v: u64) -> [Fp; RATE] {
    let mut d = [Fp::ZERO; RATE];
    d[0] = Fp::from_u64(v);
    d
}

fn opened(t: &PoolTree, leaf_index: usize) -> Witnessed {
    Witnessed {
        leaf_index,
        siblings: t.path(leaf_index).0,
    }
}

fn main() {
    let out = std::env::args().nth(1).unwrap_or_else(|| "spend.wit".into());
    let h = hasher();

    let sks = [secret(1), secret(2)];
    let inputs = [owned(sks[0], 0, 1000), owned(sks[1], 0, 2000)];
    let outputs = [plain(20, 1500), plain(30, 1200)];
    let cms = [note_parts(&inputs[0]).cm, note_parts(&inputs[1]).cm];

    // The pool holds the two spent notes and nothing else, at leaves 0 and 1.
    let mut pool = PoolTree::with_depth(h.clone(), DEPTH);
    let pool_leaves: Vec<usize> = cms.iter().map(|cm| pool.insert(*cm)).collect();

    // The association set holds three pads first, so the same notes land at 3
    // and 4 and the two roots differ.
    let mut assoc = PoolTree::with_depth(h.clone(), DEPTH);
    for p in ASSOC_PADS {
        assoc.insert(pad(p));
    }
    let assoc_leaves: Vec<usize> = cms.iter().map(|cm| assoc.insert(*cm)).collect();

    let w = SpendWitness {
        depth: DEPTH,
        secrets: sks,
        inputs,
        outputs,
        pool: [opened(&pool, pool_leaves[0]), opened(&pool, pool_leaves[1])],
        note_root: pool.root(),
        assoc: [opened(&assoc, assoc_leaves[0]), opened(&assoc, assoc_leaves[1])],
        assoc_root: assoc.root(),
        public_amount: PUBLIC_AMOUNT,
        fee: FEE,
        asset_id: 0,
        clearing_price: CLEARING_PRICE,
        recipient: address_limbs(&address_from_u64(RECIPIENT)),
        fee_recipient: address_limbs(&address_from_u64(FEE_RECIPIENT)),
    };

    /*
     * The spend has to balance before it is written. A witness that does not is
     * a file the prover will refuse for a reason that is about the wallet's
     * arithmetic and not about anything this tool is testing, and finding that
     * out after a proof has run is finding it out late.
     */
    let inn: u64 = w.inputs.iter().map(|n: &Note| n.value).sum();
    let outv: u64 = w.outputs.iter().map(|n: &Note| n.value).sum();
    assert_eq!(
        inn,
        outv + w.public_amount + w.fee,
        "the fixture does not balance: {inn} in against {outv} out plus {} public and {} fee",
        w.public_amount,
        w.fee
    );

    let words = write(&w);
    let mut bytes = Vec::with_capacity(words.len() * 8);
    for v in &words {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    std::fs::write(&out, &bytes).expect("write witness");

    /*
     * The same words as a vector, so the client can be held to them without
     * shipping a binary through a review. A client rebuilds this spend from its
     * own code and compares word for word.
     *
     * A witness is the private half of a spend, so this file carries both spend
     * secrets in the clear, at words 2 through 9. That is the point of it and it
     * is also a standing hazard: anyone holding this file derives these two
     * notes' nullifier keys and can link their spend completely. The vector
     * says so in its own first field rather than only in THREAT.md 1d, because
     * the reader who needs the warning is the one who found the file without
     * the document.
     */
    let vector = concat!(env!("CARGO_MANIFEST_DIR"), "/../spec/shield-witness.json");
    let list: Vec<String> = words.iter().map(|v| v.to_string()).collect();
    let json = format!(
        "{{\n  \"artifact\": \"shield-witness\",\n  \
         \"warning\": \"carries both spend secrets in the clear at words 2..9; \
         these notes are test value forever\",\n  \"depth\": {DEPTH},\n  \
         \"words\": {},\n  \"assoc_pads\": [{}],\n  \
         \"pool_leaves\": {:?},\n  \"assoc_leaves\": {:?},\n  \
         \"witness\": [{}]\n}}\n",
        words.len(),
        ASSOC_PADS.map(|v| v.to_string()).join(","),
        pool_leaves,
        assoc_leaves,
        list.join(",")
    );
    std::fs::write(vector, &json).expect("write witness vector");
    println!("wrote {vector}");
    println!(
        "wrote {out}, {} words at depth {DEPTH}, pool leaves {:?}, assoc leaves {:?}",
        words.len(),
        pool_leaves,
        assoc_leaves
    );
}
