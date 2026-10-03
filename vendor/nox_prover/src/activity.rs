// NONOS Operating System (AGPL-3.0-or-later)
//! A weekly activity claim, proved on the device that holds the key.
//!
//! The request is the week as published beside its root, and the spends the
//! wallet made in it:
//!
//! ```text
//! { "week": 2934,
//!   "root": "0x…",                       Λ_e, the root the claim is made against
//!   "leaves": ["0x…", …],                the week's NullifierSpent digests, in chain order
//!   "cms": ["0x…", …],                   up to four of the wallet's spent notes' commitments
//!   "note_positions": [17, …],           each note's position in the note tree
//!   "payout_address": "0x…" }            the holder's mainnet address, 20 bytes
//! ```
//!
//! P is the address in four limbs of 48, 48, 48 and 16 bits, low first, as
//! the pool writes an address and as `PayoutAddress.decode` reads it
//! (`docs/rewards/payout-encoding.md` in the contracts repository). The zero
//! address is refused: it is paid as written, so a wallet never names it.
//!
//! The seed is the spending secret, `{ "sk": [a, b, c, d] }`; the key `nk` is
//! derived from it as for transfers. The leaves are folded here and the claim
//! is refused unless they give `root`: a wallet never proves against a week it
//! has not rebuilt. Each note's nullifier is found among the leaves and the
//! slots are filled in leaf order, which is the order the circuit requires.
//!
//! The answer is `{ "proof": "<format 7, hex>", "publics": ["…", …] }`, the
//! eighteen words as decimal strings, verified before it is returned.

use stark_proofs::activity::{
    key_commitment, nullifier, prove, tag, Slot, Statement, Witness, DEPTH, LOG_ROUNDS, SLOTS,
};
use stark_proofs::crypto::stark::air::{Poseidon, RATE};
use stark_proofs::crypto::stark::field::Fp;
use stark_proofs::host::{try_unpack_digest, Json};
use stark_proofs::shield::key::derive;
use stark_proofs::shield::member::PoolTree;

/// Prove the activity claim `request` describes, with the key from `seed`.
pub fn prove_activity(
    request: &str,
    seed: &str,
    entropy: &[u8],
) -> Result<(Vec<u8>, Vec<u64>), String> {
    let r = Json(request);
    let week = r.try_u64("week")?;
    let root = try_unpack_digest(r.try_string("root")?)?;
    let payout = payout_words(r.try_string("payout_address")?)?;
    let leaves = r
        .try_strings("leaves")?
        .into_iter()
        .map(try_unpack_digest)
        .collect::<Result<Vec<_>, _>>()?;
    let cms = r
        .try_strings("cms")?
        .into_iter()
        .map(try_unpack_digest)
        .collect::<Result<Vec<_>, _>>()?;
    let note_positions = r.try_u64s("note_positions")?;
    if cms.is_empty() || cms.len() > SLOTS || cms.len() != note_positions.len() {
        return Err(format!(
            "one to {SLOTS} spends, each with its note position"
        ));
    }
    if leaves.len() > 1 << DEPTH {
        return Err(format!(
            "{} leaves do not fit a depth {DEPTH} tree",
            leaves.len()
        ));
    }

    let sk = Json(seed).try_u64s("sk")?;
    let sk: [u64; RATE] = sk
        .try_into()
        .map_err(|_| "the seed's sk is four words".to_string())?;
    let h = Poseidon::new(LOG_ROUNDS, [Fp::ZERO; RATE]);
    let nk = derive(&h, sk.map(Fp::from_u64)).nk;

    let mut tree = PoolTree::with_depth(h, DEPTH);
    for l in &leaves {
        tree.insert(*l);
    }
    if tree.root() != root {
        return Err(
            "the leaves do not fold to the root; refusing to prove against this week".into(),
        );
    }

    let mut found = Vec::with_capacity(cms.len());
    for (cm, &pos) in cms.iter().zip(&note_positions) {
        let nf = nullifier(nk, *cm, pos);
        let at = leaves.iter().position(|l| *l == nf).ok_or_else(|| {
            format!("the spend at note position {pos} is not among this week's nullifiers")
        })?;
        if found.iter().any(|&(a, _, _)| a == at) {
            return Err(format!("the spend at note position {pos} is named twice"));
        }
        found.push((at, *cm, pos));
    }
    found.sort_unstable_by_key(|&(at, _, _)| at);

    let mut slots: [Option<Slot>; SLOTS] = Default::default();
    for (j, &(at, cm, note_position)) in found.iter().enumerate() {
        let (siblings, right) = tree.path(at);
        slots[j] = Some(Slot {
            cm,
            note_position,
            siblings,
            right,
        });
    }
    let st = Statement::new(
        root,
        week,
        found.len() as u64,
        tag(nk, week),
        payout,
        key_commitment(nk),
    )
    .ok_or("a count of one to four")?;
    let bytes = prove(&st, &Witness { nk, slots }, entropy).map_err(|e| format!("{e:?}"))?;
    Ok((bytes, st.words().iter().map(|v| v.to_u64()).collect()))
}

/// A mainnet address as P: 48, 48, 48 and 16 bits, low first.
pub fn payout_words(address: &str) -> Result<[Fp; RATE], String> {
    let h = address.trim().strip_prefix("0x").unwrap_or(address.trim());
    if h.len() != 40 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{address} is not a 20-byte address"));
    }
    let bytes: Vec<u8> = (0..20)
        .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    if bytes.iter().all(|&b| b == 0) {
        return Err("the zero address is never a payout".into());
    }
    // Bit i of the address, counting from the least significant.
    let bit = |i: usize| (bytes[19 - i / 8] >> (i % 8)) & 1;
    let limb = |from: usize, width: usize| {
        (0..width).fold(0u64, |acc, k| acc | (bit(from + k) as u64) << k)
    };
    Ok([limb(0, 48), limb(48, 48), limb(96, 48), limb(144, 16)].map(Fp::from_u64))
}

/// The answer as the wallet stores it.
pub fn to_json(proof: &[u8], publics: &[u64]) -> String {
    let hex: String = proof.iter().map(|b| format!("{b:02x}")).collect();
    let words: Vec<String> = publics.iter().map(|w| format!("\"{w}\"")).collect();
    format!(
        "{{\"proof\": \"{hex}\", \"publics\": [{}]}}",
        words.join(", ")
    )
}
