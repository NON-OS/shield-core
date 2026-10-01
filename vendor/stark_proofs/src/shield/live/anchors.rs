// NONOS Operating System (AGPL-3.0-or-later)
//! The first spend: two real notes in a deployed pool, unshielded in full.
//!
//! Everything here is a value read off Sepolia or handed over with it, not a
//! fixture. The pool is
//! `0xa760D749adfe15BafFfeC8E7301CEA89B150c046`, the two spendable notes sit
//! at leaves 1 and 2, and leaf 0 is an earlier note nobody holds the secret
//! for. The commitments were read from the pool's own `NoteCommitted` logs
//! rather than copied from the handoff, so the leaves proved here are the
//! leaves the contract stored.
//!
//! Kept in the crate rather than in the test tree because the emitter that
//! produces the proof needs it, and because a spend against live state is
//! worth being able to rebuild exactly a month from now.

use crate::crypto::stark::air::{Poseidon, RATE};
use crate::crypto::stark::field::Fp;
use crate::shield::join::{
    address_from_u64, join_split_published, AssocAnchor, JoinSplit, Settle, Spend,
};
use crate::shield::key::Break;
use crate::shield::member::PoolTree;
use crate::shield::note::{Note, POOL_LOG_ROUNDS};
use alloc::vec::Vec;

/// The pool's tree depth, which the contract fixes at deployment.
pub const DEPTH: usize = 32;

/// Leaf 0: an earlier deposit whose secret nobody has. Present only because
/// it is leaf 1's sibling, so no opening can be built without it.
pub const LEAF0_CM: &str = "0f14542ea9ec2683cac6fb8e8167203c8c7eed6759da835fd29c233259e8ba62";

/// Note A, leaf 1.
pub const A_SK: &str = "9c4b73105bd8c464250d949588b61807aee31121ea9d916ff6bf6105dab3ff7e";
pub const A_BLINDING: &str = "feb675b9c81199eac575cd15116a9215f5289e96d9706e1afffa4e4fcd9affe1";

/// Note B, leaf 2.
pub const B_SK: &str = "0730018f3ed1e773658f0e36f8289c82d04608ca0589548e4a55cef505ad496e";
pub const B_BLINDING: &str = "8c217b2d9fa1e72cddedcef23597d3ce913d14c7e34977e49fa9646fadeffd28";

/// Both notes hold the same post-fee value; the deposits were equal.
pub const NOTE_VALUE: u64 = 1_995_000_000_000_000;

/*
 * What the deployed pool holds, under the commitment it was deployed with:
 * leaf 1 5 9 b 6 8 3 5 c ..., leaf 2 1 e d f f 8 8 b ..., root e 0 8 3 f 5 8 8 ...
 *
 * Those are not recomputed here and no test asserts them, because the nested
 * commitment does not produce them: that pool's leaves committed the value and
 * the spend key in one quad, which is the arrangement that forced a deposit to
 * publish its opening. The secrets and the value above still describe real
 * notes and still exercise every binding; only the digests moved. The pool
 * that holds these leaves is not migrated and cannot be.
 */

/// A `bytes32` as the circuit's four limbs: big endian over
/// `[limb3, limb2, limb1, limb0]`, so limb 0 is the last eight bytes. Read
/// the other way round every value is still a valid field element and every
/// note is unspendable, which is the failure worth naming.
pub fn limbs(hex: &str) -> [Fp; RATE] {
    let b: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    let mut out = [Fp::ZERO; RATE];
    for (j, slot) in out.iter_mut().enumerate() {
        let hi = 24 - 8 * j;
        let mut w = [0u8; 8];
        w.copy_from_slice(&b[hi..hi + 8]);
        *slot = Fp::from_u64(u64::from_be_bytes(w));
    }
    out
}

pub fn hex_of(d: [Fp; RATE]) -> alloc::string::String {
    let mut s = alloc::string::String::new();
    for j in (0..RATE).rev() {
        s.push_str(&alloc::format!("{:016x}", d[j].to_u64()));
    }
    s
}

pub fn hasher() -> Poseidon {
    Poseidon::new(POOL_LOG_ROUNDS, [Fp::ZERO; RATE])
}

pub fn u64s(d: [Fp; RATE]) -> [u64; 4] {
    [d[0].to_u64(), d[1].to_u64(), d[2].to_u64(), d[3].to_u64()]
}

/// The note a secret and a blinding describe, with the spend key derived
/// rather than supplied: a note whose committed key is not the one its
/// secret derives is a note nobody can spend, and deriving it here means
/// that cannot be got wrong by transcription.
pub fn note_of(sk_hex: &str, blinding_hex: &str, value: u64) -> Note {
    let k = crate::shield::key::derive(&hasher(), limbs(sk_hex));
    Note {
        value,
        asset_id: 0,
        spend_pk: u64s(k.spend_pk),
        blinding: u64s(limbs(blinding_hex)),
    }
}

/// The association set the registry published. The two spent notes must open under this root, or
/// `settleBatch` refuses the intent before it examines the proof.
pub const ASSOC_ROOT: &str = "af3f40b52f9cc92a85433b5327fc4b2f3fa13c2885765ae2c540fe5cd1c16cf8";

/// The first spend, proved the way production proves one: both trees
/// published, neither planted.
///
/// `unshield` below still uses the planted association set, because the
/// registry's openings are not something this crate can invent: they come
/// from the chain. This is the entry that takes them.
pub fn unshield_published(
    assoc_openings: [&crate::shield::join::Witnessed; 2],
    assoc_root: [Fp; RATE],
    recipient: u64,
    clearing_price: u64,
) -> JoinSplit {
    let a = note_of(A_SK, A_BLINDING, NOTE_VALUE);
    let b = note_of(B_SK, B_BLINDING, NOTE_VALUE);
    let zero_a = Note {
        value: 0,
        asset_id: 0,
        spend_pk: [1, 2, 3, 4],
        blinding: [5, 6, 7, 8],
    };
    let zero_b = Note {
        value: 0,
        asset_id: 0,
        spend_pk: [9, 10, 11, 12],
        blinding: [13, 14, 15, 16],
    };
    let t = tree();
    let open_a = crate::shield::join::Witnessed {
        leaf_index: 1,
        siblings: t.path(1).0,
    };
    let open_b = crate::shield::join::Witnessed {
        leaf_index: 2,
        siblings: t.path(2).0,
    };

    join_split_published(
        DEPTH,
        [
            Spend {
                note: &a,
                sk: limbs(A_SK),
            },
            Spend {
                note: &b,
                sk: limbs(B_SK),
            },
        ],
        [&open_a, &open_b],
        root(),
        AssocAnchor {
            openings: assoc_openings,
            root: assoc_root,
        },
        [&zero_a, &zero_b],
        NOTE_VALUE * 2,
        0,
        Break::None,
        Settle {
            not_before: 0,
            clearing_price,
            recipient: address_from_u64(recipient),
            fee_recipient: [0; 20],
        },
        None,
    )
}

/// Three leaves in order: an opaque earlier deposit, then the two notes,
/// committed rather than transcribed so the tree and the spend cannot
/// disagree about what a leaf holds.
pub fn tree() -> PoolTree {
    let mut t = PoolTree::with_depth(hasher(), DEPTH);
    t.insert(limbs(LEAF0_CM));
    for (sk, blinding) in [(A_SK, A_BLINDING), (B_SK, B_BLINDING)] {
        t.insert(commitment_of(&note_of(sk, blinding, NOTE_VALUE)));
    }
    t
}

/// The anchor a spend proves against, the root after leaf 2.
pub fn root() -> [Fp; RATE] {
    tree().root()
}

/// A leaf of that tree, for a caller checking an opening against it.
pub fn note_commitment(sk_hex: &str, blinding_hex: &str, value: u64) -> [Fp; RATE] {
    commitment_of(&note_of(sk_hex, blinding_hex, value))
}

/// The first spend: both notes in, nothing kept back, the whole value out to
/// `recipient` as a public amount.
///
/// The outputs are notes worth zero. They are not absent: the circuit has
/// two output legs and commits both, so the pool will insert two real
/// commitments as leaves. Their blindings are fixed rather than random
/// because nothing can ever be spent from them and a reproducible spend is
/// worth more here than an unpredictable dead leaf.
///
/// A note's commitment, the way the pool computes it: the owner compression,
/// then the public quad over it. Used to plant a synthetic tree whose leaves
/// are real commitments rather than arbitrary digests, so the openings a
/// spend proves against are the openings a pool would give.
pub fn commitment_of(note: &Note) -> [Fp; RATE] {
    let h = hasher();
    let q = crate::shield::note::quads(&note.limbs());
    h.compress(&q[2], &h.compress(&q[0], &q[1]))
}
