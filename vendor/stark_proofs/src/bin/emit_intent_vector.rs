// NONOS Operating System (AGPL-3.0-or-later)
//! Writes spec/shield-intent.json: one transfer, every input that defines it,
//! and the thirty-six words the pool settles.
//!
//! Half of the client-prover seam is checkable without a prover: the client
//! and the circuit have to agree
//! on what a transfer *is*. Two implementations of one statement, in two
//! languages, is where seams are found, and the intent is where the two meet:
//! a client builds these words to hand a relayer,
//! and the circuit binds each of them to the cell that computes it.
//!
//! Every input is emitted beside the output, not just the result. A vector that
//! published thirty-six words and not the notes behind them would be a number a
//! reader can check the arithmetic of and not the premise, which is the failure
//! this codebase spent two days on.
//!
//! The fixture is integers on purpose. Secrets, blindings and leaf positions all
//! descend from small seeds, so a Zig client can build the same spend from this
//! file alone without sharing a random number generator with Rust.

use stark_proofs::crypto::stark::air::RATE;
use stark_proofs::crypto::stark::field::Fp;
use stark_proofs::shield::join::{address_from_u64, join_split_at, Settle, Spend};
use stark_proofs::shield::key::Break;
use stark_proofs::shield::note::{note_parts, Note};
use stark_proofs::shield::test::depth::DEPLOYED;
use stark_proofs::shield::test::fixture::{owned, plain, secret};

/// The seeds the whole spend descends from. Changing one changes every word
/// below and the client's copy has to change with it, which is what the
/// agreement gate is for.
const SK_A: u64 = 1;
const SK_B: u64 = 2;
const IN0_SEED: u64 = 0;
const IN1_SEED: u64 = 0;
const OUT0_SEED: u64 = 20;
const OUT1_SEED: u64 = 30;
const IN0_VALUE: u64 = 1000;
const IN1_VALUE: u64 = 2000;
const OUT0_VALUE: u64 = 1500;
const OUT1_VALUE: u64 = 1200;
const PUBLIC_AMOUNT: u64 = 200;
const FEE: u64 = 100;
const CLEARING_PRICE: u64 = 1_000_000;
const RECIPIENT: u64 = 0xBEEF;
/// The submitter the fee pays: named because the fee is nonzero.
const FEE_RECIPIENT: u64 = 0xFEE;

/// The pads the planted association set holds before the two spent notes, and
/// therefore the leaves the notes land on. Emitted rather than left as a
/// convention two languages would each have to know: the pool plants the two
/// commitments at 0 and 1, the association set plants three pads first and the
/// commitments at 3 and 4.
const ASSOC_PADS: [u64; 3] = [900, 901, 902];
const POOL_LEAVES: [usize; 2] = [0, 1];
const ASSOC_LEAVES: [usize; 2] = [3, 4];

fn list(d: &[Fp]) -> String {
    let v: Vec<String> = d.iter().map(|x| x.value().to_string()).collect();
    format!("[{}]", v.join(","))
}

fn note_json(n: &Note) -> String {
    format!(
        "{{\"value\":{},\"asset_id\":{},\"spend_pk\":[{}],\"blinding\":[{}]}}",
        n.value,
        n.asset_id,
        n.spend_pk.map(|v| v.to_string()).join(","),
        n.blinding.map(|v| v.to_string()).join(",")
    )
}

fn main() {
    let out = std::env::args().nth(1).unwrap_or_else(|| {
        concat!(env!("CARGO_MANIFEST_DIR"), "/../spec/shield-intent.json").into()
    });

    let sks = [secret(SK_A), secret(SK_B)];
    let ins = [
        owned(sks[0], IN0_SEED, IN0_VALUE),
        owned(sks[1], IN1_SEED, IN1_VALUE),
    ];
    let outs = [plain(OUT0_SEED, OUT0_VALUE), plain(OUT1_SEED, OUT1_VALUE)];

    let js = join_split_at(
        DEPLOYED,
        [
            Spend {
                note: &ins[0],
                sk: sks[0],
            },
            Spend {
                note: &ins[1],
                sk: sks[1],
            },
        ],
        [&outs[0], &outs[1]],
        PUBLIC_AMOUNT,
        FEE,
        Break::None,
        Settle {
            not_before: 0,
            clearing_price: CLEARING_PRICE,
            recipient: address_from_u64(RECIPIENT),
            fee_recipient: address_from_u64(FEE_RECIPIENT),
        },
        None,
    );

    /*
     * The two spent commitments, so a client can rebuild both trees from this
     * file rather than from a convention. Insert these at POOL_LEAVES into an
     * empty tree of `depth` and the root is words 0 to 3; insert the pads then
     * these at ASSOC_LEAVES and the root is words 4 to 7. Agreeing on those two
     * roots is agreeing on the membership the circuit proves.
     */
    let in_cms = [note_parts(&ins[0]).cm, note_parts(&ins[1]).cm];

    assert_eq!(
        js.intent.len(),
        36,
        "the settled statement is thirty-six words; the client pins that count"
    );

    /*
     * The word order is SPEC section 6 and the client indexes by it: note root,
     * association root, two nullifiers, two commitments, then the four scalars
     * and the recipient, then the fee recipient. Emitted as named offsets beside the words so a reader
     * never counts.
     */
    let json = format!(
        "{{\n  \"artifact\": \"shield-intent\",\n  \"depth\": {},\n  \
         \"words\": {},\n  \
         \"offsets\": {{\"note_root\":0,\"assoc_root\":4,\"nf0\":8,\"nf1\":12,\
         \"out_cm0\":16,\"out_cm1\":20,\"public_amount\":24,\"fee\":25,\
         \"asset_id\":26,\"clearing_price\":27,\"recipient\":28,\"fee_recipient\":32}},\n  \
         \"secrets\": [{},{}],\n  \
         \"inputs\": [{},{}],\n  \"outputs\": [{},{}],\n  \
         \"input_cms\": [{},{}],\n  \
         \"assoc_pads\": [{},{},{}],\n  \
         \"pool_leaves\": [{},{}],\n  \"assoc_leaves\": [{},{}],\n  \
         \"public_amount\": {},\n  \"fee\": {},\n  \"asset_id\": 0,\n  \
         \"clearing_price\": {},\n  \"recipient\": {},\n  \"fee_recipient\": {},\n  \
         \"intent\": {}\n}}\n",
        DEPLOYED,
        js.intent.len(),
        list(&sks[0]),
        list(&sks[1]),
        note_json(&ins[0]),
        note_json(&ins[1]),
        note_json(&outs[0]),
        note_json(&outs[1]),
        list(&in_cms[0]),
        list(&in_cms[1]),
        ASSOC_PADS[0],
        ASSOC_PADS[1],
        ASSOC_PADS[2],
        POOL_LEAVES[0],
        POOL_LEAVES[1],
        ASSOC_LEAVES[0],
        ASSOC_LEAVES[1],
        PUBLIC_AMOUNT,
        FEE,
        CLEARING_PRICE,
        RECIPIENT,
        FEE_RECIPIENT,
        list(&js.intent),
    );

    std::fs::write(&out, &json).expect("write intent vector");
    println!("wrote {out}, {} words at depth {DEPLOYED}", js.intent.len());
    let _ = RATE;
}
