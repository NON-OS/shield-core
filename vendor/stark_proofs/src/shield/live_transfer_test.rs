// NONOS Operating System (AGPL-3.0-or-later)
//! A transfer takes nothing out of the pool, which is the case the system
//! exists for. Every test in live_test is an unshield, where the amount is
//! public by construction.

use super::live::*;
use crate::crypto::stark::air::RATE;
use crate::crypto::stark::field::Fp;
use crate::shield::join::{address_from_u64, join_split_with_paths};
use crate::shield::join::{Settle, Spend, Witnessed};
use crate::shield::key::Break;
use crate::shield::note::Note;
use crate::witness_satisfies_public;

/// The burner named as the payout address.
const BURNER: u64 = 0x7408_ae4c;

/// A private transfer: nothing leaves the pool.
///
/// Every other test here is an unshield, where the value exits to a named
/// address and the amount is public by construction. A transfer is the
/// case the system exists for: public amount zero, fee zero, and the
/// whole value carried into two fresh output notes. What the chain sees
/// is two nullifiers retiring and two commitments appearing. It does not
/// see which notes were spent, what they were worth, or who now holds
/// them.
///
/// Conservation still has to close, and it closes at zero: inputs equal
/// outputs exactly.
#[test]
fn a_private_transfer_satisfies_and_reveals_no_amount() {
    let a = note_of(A_SK, A_BLINDING, NOTE_VALUE);
    let b = note_of(B_SK, B_BLINDING, NOTE_VALUE);

    /*
     * The value split unevenly between the outputs on purpose: an equal
     * split could be satisfied by a circuit that only checked the total
     * twice, and the point is that the split itself is unconstrained
     * except by conservation.
     */
    let out_a = Note {
        value: NOTE_VALUE + NOTE_VALUE / 4,
        asset_id: 0,
        spend_pk: [0xA1, 0xA2, 0xA3, 0xA4],
        blinding: [0xB1, 0xB2, 0xB3, 0xB4],
    };
    let out_b = Note {
        value: NOTE_VALUE - NOTE_VALUE / 4,
        asset_id: 0,
        spend_pk: [0xC1, 0xC2, 0xC3, 0xC4],
        blinding: [0xD1, 0xD2, 0xD3, 0xD4],
    };
    assert_eq!(
        out_a.value + out_b.value,
        NOTE_VALUE * 2,
        "the transfer must conserve"
    );

    let t = tree();
    let open_a = crate::shield::join::Witnessed {
        leaf_index: 1,
        siblings: t.path(1).0,
    };
    let open_b = crate::shield::join::Witnessed {
        leaf_index: 2,
        siblings: t.path(2).0,
    };
    let js = join_split_with_paths(
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
        [&out_a, &out_b],
        0,
        0,
        Break::None,
        Settle {
            not_before: 0,
            clearing_price: 1_000_000,
            recipient: address_from_u64(0),
            fee_recipient: [0; 20],
        },
        None,
    );
    assert!(
        witness_satisfies_public(&js.wired, &js.witness),
        "a private transfer does not satisfy its own constraints"
    );

    /*
     * The public amount really is zero in the declared intent, and the
     * declared output commitments really are the two new notes. If the
     * amount were non-zero the transfer would be an unshield wearing a
     * transfer's name, and the pool would move value.
     */
    use crate::shield::join::publics::{OUT_CM0, OUT_CM1, PUBLIC_AMOUNT};
    assert_eq!(
        js.intent[PUBLIC_AMOUNT],
        Fp::ZERO,
        "a transfer must declare no public amount"
    );
    let declared_a: [Fp; RATE] = [
        js.intent[OUT_CM0],
        js.intent[OUT_CM0 + 1],
        js.intent[OUT_CM0 + 2],
        js.intent[OUT_CM0 + 3],
    ];
    let declared_b: [Fp; RATE] = [
        js.intent[OUT_CM1],
        js.intent[OUT_CM1 + 1],
        js.intent[OUT_CM1 + 2],
        js.intent[OUT_CM1 + 3],
    ];
    assert_eq!(
        declared_a,
        commitment_of(&out_a),
        "output 0 is not the note that was created"
    );
    assert_eq!(
        declared_b,
        commitment_of(&out_b),
        "output 1 is not the note that was created"
    );
}

/// What a transfer publishes, word for word.
///
/// Hiding the amount is not privacy on its own. The intent is 32 public
/// words and every one of them lands on chain, so the question is which of
/// them a transfer has any business setting. The anchors, the two
/// nullifiers and the two output commitments have to be there. A payout
/// address and a clearing price belong to a settlement, and a transfer
/// settles nothing, so a non-zero value in either is either a field the
/// sender can be identified by or a channel it can be tagged through.
///
/// Built asking for both, so this is a property of the circuit rather than
/// an observation that the caller passed zeros.
#[test]
fn a_transfer_reveals_only_its_anchors_and_its_notes() {
    use crate::shield::join::publics::{
        ASSET_ID, CLEARING_PRICE, FEE, PUBLIC_AMOUNT, RECIPIENT, WORDS,
    };

    let a = note_of(A_SK, A_BLINDING, NOTE_VALUE);
    let b = note_of(B_SK, B_BLINDING, NOTE_VALUE);
    let out_a = Note {
        value: NOTE_VALUE + NOTE_VALUE / 4,
        asset_id: 0,
        spend_pk: [0xA1, 0xA2, 0xA3, 0xA4],
        blinding: [0xB1, 0xB2, 0xB3, 0xB4],
    };
    let out_b = Note {
        value: NOTE_VALUE - NOTE_VALUE / 4,
        asset_id: 0,
        spend_pk: [0xC1, 0xC2, 0xC3, 0xC4],
        blinding: [0xD1, 0xD2, 0xD3, 0xD4],
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
    let js = join_split_with_paths(
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
        [&out_a, &out_b],
        0,
        0,
        Break::None,
        Settle {
            not_before: 0,
            clearing_price: 1_000_000,
            recipient: address_from_u64(0x7408_ae4c),
            fee_recipient: [0; 20],
        },
        None,
    );

    assert!(
        witness_satisfies_public(&js.wired, &js.witness),
        "the transfer does not satisfy, so what it publishes is not the question yet"
    );
    assert_eq!(js.intent.len(), WORDS);
    assert_eq!(
        js.intent[PUBLIC_AMOUNT],
        Fp::ZERO,
        "a transfer moves nothing publicly"
    );

    let leaked: alloc::vec::Vec<(&str, usize, u64)> = [
        ("recipient", RECIPIENT),
        ("recipient", RECIPIENT + 1),
        ("recipient", RECIPIENT + 2),
        ("recipient", RECIPIENT + 3),
        ("clearing_price", CLEARING_PRICE),
        ("asset_id", ASSET_ID),
        ("fee", FEE),
    ]
    .into_iter()
    .filter(|&(_, i)| js.intent[i] != Fp::ZERO)
    .map(|(n, i)| (n, i, js.intent[i].to_u64()))
    .collect();

    assert!(
        leaked.is_empty(),
        "a transfer published settlement fields it has no use for: {leaked:?}"
    );
}

/// A transfer that creates more value than it spends must fail, which is
/// the minting case conservation exists to stop.
#[test]
fn a_transfer_that_creates_value_is_refused() {
    let a = note_of(A_SK, A_BLINDING, NOTE_VALUE);
    let b = note_of(B_SK, B_BLINDING, NOTE_VALUE);
    let out_a = Note {
        value: NOTE_VALUE + 1,
        asset_id: 0,
        spend_pk: [0xA1, 0xA2, 0xA3, 0xA4],
        blinding: [0xB1, 0xB2, 0xB3, 0xB4],
    };
    let out_b = Note {
        value: NOTE_VALUE,
        asset_id: 0,
        spend_pk: [0xC1, 0xC2, 0xC3, 0xC4],
        blinding: [0xD1, 0xD2, 0xD3, 0xD4],
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
    let js = join_split_with_paths(
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
        [&out_a, &out_b],
        0,
        0,
        Break::None,
        Settle {
            not_before: 0,
            clearing_price: 1_000_000,
            recipient: address_from_u64(0),
            fee_recipient: [0; 20],
        },
        None,
    );
    assert!(
        !witness_satisfies_public(&js.wired, &js.witness),
        "a transfer minted a wei out of nothing"
    );
}

/// Conservation is the only thing between an unshield and minting, so
/// claiming one wei more than the two notes hold must fail.
#[test]
fn claiming_more_than_the_notes_hold_is_refused() {
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
    let (a_sibs, _) = t.path(1);
    let (b_sibs, _) = t.path(2);
    let open_a = Witnessed {
        leaf_index: 1,
        siblings: a_sibs,
    };
    let open_b = Witnessed {
        leaf_index: 2,
        siblings: b_sibs,
    };
    let js = join_split_with_paths(
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
        NOTE_VALUE * 2 + 1,
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
        "the circuit accepted a spend claiming more than its notes hold"
    );
}
