// NONOS Operating System (AGPL-3.0-or-later)

use super::live::*;
use crate::crypto::stark::air::RATE;
use crate::crypto::stark::field::Fp;
use crate::shield::join::{address_from_u64, join_split_with_paths};
use crate::shield::join::{Settle, Spend, Witnessed};
use crate::shield::key::Break;
use crate::shield::member::PoolTree;
use crate::shield::note::Note;
use crate::witness_satisfies_public;

/// The burner named as the payout address.
const BURNER: u64 = 0x7408_ae4c;

/// Both notes open to the anchor the spend proves against. The pool's own
/// tree hashing is checked against its deployed leaves and root in
/// `test::live_pool`; this checks that the leaves a spend commits are the
/// leaves the tree it walks actually holds.
#[test]
fn both_notes_open_to_the_anchor_the_spend_proves_against() {
    let t = tree();
    let h = hasher();
    for (index, sk, blinding) in [(1usize, A_SK, A_BLINDING), (2usize, B_SK, B_BLINDING)] {
        let cm = note_commitment(sk, blinding, NOTE_VALUE);
        let (sibs, dirs) = t.path(index);
        let mut node = cm;
        for (sib, right) in sibs.iter().zip(dirs.iter()) {
            node = if *right {
                h.compress(sib, &node)
            } else {
                h.compress(&node, sib)
            };
        }
        assert_eq!(node, root(), "leaf {index} does not open to the anchor");
    }
}

/// The spend satisfies its own constraints against the live root. This is
/// the statement a server will spend an hour proving, so it is worth
/// knowing in a second that it closes.
#[test]
fn the_first_spend_satisfies() {
    let js = unshield(BURNER, 1_000_000);
    assert!(
        witness_satisfies_public(&js.wired, &js.witness),
        "the first spend does not satisfy its own constraints"
    );
}

/// The three tests that tell the real circuit from a conservation-only
/// fixture. The test above establishes conservation and nothing else, and a wired
/// accumulator with a range check passes it too.
///
/// Each spends the live notes and breaks exactly one property. All three
/// must fail to satisfy; if any passes, that property is not constrained
/// and the circuit is not proving what the pool believes it proves.
fn live_spend_broken(brk: Break) -> crate::shield::join::JoinSplit {
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
    let open_a = Witnessed {
        leaf_index: 1,
        siblings: t.path(1).0,
    };
    let open_b = Witnessed {
        leaf_index: 2,
        siblings: t.path(2).0,
    };
    join_split_with_paths(
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
        [&zero_a, &zero_b],
        NOTE_VALUE * 2,
        0,
        brk,
        Settle {
            not_before: 0,
            clearing_price: 1_000_000,
            recipient: address_from_u64(BURNER),
            fee_recipient: [0; 20],
        },
        None,
    )
}

/// Ownership. A note whose committed spend key this secret did not derive
/// must not be spendable, or holding a commitment is enough to spend it.
///
/// Built by hand rather than through `Break::NotOwner`. That variant is
/// declared and documented in the tamper enum and applied nowhere:
/// `nullifier_parts` handles the other four and falls through on it, and
/// nothing else in the tree reads it. A test written against it passes
/// because no tamper happens, which is the worst kind of green. The note
/// below carries a spend key no secret derived, and the secret offered
/// for it is the one that owns a different note.
#[test]
fn a_note_this_secret_does_not_own_is_unspendable() {
    let stolen = Note {
        value: NOTE_VALUE,
        asset_id: 0,
        spend_pk: [0xBAD, 0xBAD1, 0xBAD2, 0xBAD3],
        blinding: u64s(limbs(A_BLINDING)),
    };
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

    /*
     * The stolen note is genuinely a leaf of the tree it is proved
     * against, so membership holds and only ownership is in question.
     * Anything else would fail for the wrong reason and prove nothing
     * about ownership.
     */
    let mut tr = PoolTree::with_depth(hasher(), DEPTH);
    tr.insert(limbs(LEAF0_CM));
    let ia = tr.insert(commitment_of(&stolen));
    let ib = tr.insert(commitment_of(&b));
    let open_a = Witnessed {
        leaf_index: ia,
        siblings: tr.path(ia).0,
    };
    let open_b = Witnessed {
        leaf_index: ib,
        siblings: tr.path(ib).0,
    };

    let js = join_split_with_paths(
        DEPTH,
        [
            Spend {
                note: &stolen,
                sk: limbs(A_SK),
            },
            Spend {
                note: &b,
                sk: limbs(B_SK),
            },
        ],
        [&open_a, &open_b],
        tr.root(),
        [&zero_a, &zero_b],
        NOTE_VALUE * 2,
        0,
        Break::None,
        Settle {
            not_before: 0,
            clearing_price: 1_000_000,
            recipient: address_from_u64(BURNER),
            fee_recipient: [0; 20],
        },
        None,
    );
    assert!(
        !witness_satisfies_public(&js.wired, &js.witness),
        "a note was spent by a secret that did not derive its committed key"
    );
}

/// Membership. Absorbing a commitment other than the one the opening
/// proved must fail, or a note never inserted under the declared root can
/// be spent.
#[test]
fn a_note_the_opening_did_not_prove_is_unspendable() {
    let js = live_spend_broken(Break::ForeignNote);
    assert!(
        !witness_satisfies_public(&js.wired, &js.witness),
        "a commitment other than the one membership proved was spent"
    );
}

/// Nullifier correctness, in the form that matters: the leaf position is
/// in the nullifier preimage, so retiring a note under a position the
/// pool did not authenticate would let one note yield two nullifiers and
/// be spent twice. Both the carrying form and the bit-zero form, because
/// bit zero is the one a higher bit's binding cannot catch.
#[test]
fn a_note_retired_under_the_wrong_position_is_unspendable() {
    for (name, brk) in [
        ("carrying", Break::ForeignIndex),
        ("bit zero", Break::ForeignIndex0),
    ] {
        let js = live_spend_broken(brk);
        assert!(
            !witness_satisfies_public(&js.wired, &js.witness),
            "a note retired under a position the pool never authenticated ({name})"
        );
    }
}

/// The nullifier key must descend from the same secret as the spend key,
/// or a commitment anyone has seen can be retired by someone who does not
/// own it.
#[test]
fn a_nullifier_key_from_another_secret_is_refused() {
    let js = live_spend_broken(Break::ForeignKey);
    assert!(
        !witness_satisfies_public(&js.wired, &js.witness),
        "the nullifier key did not have to descend from the spending secret"
    );
}

/// A spend proved against a published association set satisfies, and the
/// association root it declares is the one supplied rather than one the
/// prover planted.
///
/// The set here is synthetic because the registry's openings come from the
/// chain, but the path under test is the production one:
/// `join_split_published`, both trees supplied, nothing planted.
#[test]
fn a_spend_against_a_published_association_set_satisfies() {
    let h = hasher();
    let a = note_of(A_SK, A_BLINDING, NOTE_VALUE);
    let b = note_of(B_SK, B_BLINDING, NOTE_VALUE);

    /*
     * The two notes at odd and even association positions on purpose.
     * The column this binds through used to be chosen by the bottom
     * direction bit, so a pair straddling that bit is what would have
     * caught it.
     */
    let mut at = PoolTree::with_depth(h.clone(), DEPTH);
    at.insert([Fp::from_u64(7001); RATE]);
    let ja = at.insert(commitment_of(&a));
    let jb = at.insert(commitment_of(&b));
    assert_eq!(ja % 2, 1, "one note at an odd association position");
    assert_eq!(jb % 2, 0, "the other at an even one");
    let oa = crate::shield::join::Witnessed {
        leaf_index: ja,
        siblings: at.path(ja).0,
    };
    let ob = crate::shield::join::Witnessed {
        leaf_index: jb,
        siblings: at.path(jb).0,
    };
    let assoc_root = at.root();

    let js = unshield_published([&oa, &ob], assoc_root, BURNER, 1_000_000);
    assert!(
        witness_satisfies_public(&js.wired, &js.witness),
        "a spend against a published association set does not satisfy"
    );

    /*
     * The declared association root is the supplied one. Word 1 of the
     * intent, four limbs. If this were the planted root the pool would
     * refuse the intent with UnknownAssociationRoot no matter how good
     * the proof was.
     */
    let declared: [Fp; RATE] = [js.intent[4], js.intent[5], js.intent[6], js.intent[7]];
    assert_eq!(
        declared, assoc_root,
        "the intent declares an association root the caller did not supply"
    );
}
