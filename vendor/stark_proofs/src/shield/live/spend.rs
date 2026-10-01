// NONOS Operating System (AGPL-3.0-or-later)
//! The spend itself: the published unshield, the same spend at chosen leaves,
//! and the variant the change gate walks.

use super::anchors::{
    commitment_of, hasher, limbs, note_of, root, tree, u64s, A_BLINDING, A_SK, B_BLINDING, B_SK,
    DEPTH, NOTE_VALUE,
};
use crate::crypto::stark::air::RATE;
use crate::crypto::stark::field::Fp;
use crate::shield::join::Witnessed;
use crate::shield::join::{address_from_u64, join_split_with_paths, JoinSplit, Settle, Spend};
use crate::shield::key::Break;
use crate::shield::member::PoolTree;
use crate::shield::note::Note;

pub fn unshield(recipient: u64, clearing_price: u64) -> JoinSplit {
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

/// A spend of two notes sitting at chosen leaf positions in a tree of
/// `leaves` notes, for counting how many distinct circuits a pool needs.
///
/// Deployability does not turn on why the wiring varies, only on how many
/// ways it can vary. If the count is small and bounded, a pool launches one
/// verifier per variant and the settler declares which at open; a wrong
/// declaration is self detecting, because the periodic root will not match
/// and the walk fails. If the count grows with the leaf index, no
/// deployment exists and the circuit has to change.
pub fn unshield_at(ia: usize, ib: usize, leaves: usize, value: u64) -> JoinSplit {
    assert!(
        ia < leaves && ib < leaves && ia != ib,
        "two distinct positions inside the tree"
    );
    let h = hasher();
    let sk_a = limbs(A_SK);
    let sk_b = limbs(B_SK);
    let a = Note {
        value,
        asset_id: 0,
        spend_pk: u64s(crate::shield::key::derive(&h, sk_a).spend_pk),
        blinding: [11, 22, 33, 44],
    };
    let b = Note {
        value,
        asset_id: 0,
        spend_pk: u64s(crate::shield::key::derive(&h, sk_b).spend_pk),
        blinding: [55, 66, 77, 88],
    };
    let zero_a = Note {
        value: 0,
        asset_id: 0,
        spend_pk: [21, 22, 23, 24],
        blinding: [25, 26, 27, 28],
    };
    let zero_b = Note {
        value: 0,
        asset_id: 0,
        spend_pk: [29, 30, 31, 32],
        blinding: [33, 34, 35, 36],
    };

    let mut t = PoolTree::with_depth(h.clone(), DEPTH);
    for i in 0..leaves {
        if i == ia {
            t.insert(commitment_of(&a));
        } else if i == ib {
            t.insert(commitment_of(&b));
        } else {
            t.insert([Fp::from_u64(1000 + i as u64); RATE]);
        }
    }
    let open_a = Witnessed {
        leaf_index: ia,
        siblings: t.path(ia).0,
    };
    let open_b = Witnessed {
        leaf_index: ib,
        siblings: t.path(ib).0,
    };

    join_split_with_paths(
        DEPTH,
        [Spend { note: &a, sk: sk_a }, Spend { note: &b, sk: sk_b }],
        [&open_a, &open_b],
        t.root(),
        [&zero_a, &zero_b],
        value * 2,
        0,
        Break::None,
        Settle {
            not_before: 0,
            clearing_price: 1_000_000,
            recipient: address_from_u64(BURNER_ADDR),
            fee_recipient: [0; 20],
        },
        None,
    )
}

/// The test payout address.
pub const BURNER_ADDR: u64 = 0x7408_ae4c;

/// A second spend that differs in everything a production spend varies: a
/// different pool tree, different leaf indices, different siblings, different
/// note values, a different recipient and a different published root.
///
/// Two spends against the *same* root would share a periodic root even on a circuit
/// that baked the tree in, so that test would pass on a broken circuit. This
/// one cannot. If these two spends share a periodic set, one deployed
/// verifier serves every spend against the pool. If they do not, every spend
/// needs its own verifier and the design is undeployable.
pub fn unshield_variant() -> JoinSplit {
    let h = hasher();
    /*
     * Six leaves rather than three, the spent pair sitting at 3 and 4 rather
     * than 1 and 2, so the openings differ in length of shared prefix, in
     * direction bits and in every sibling.
     */
    let sk_a = limbs("11112222333344445555666677778888999900001111222233334444aaaa0001");
    let sk_b = limbs("22223333444455556666777788889999000011112222333344445555bbbb0002");
    let a = Note {
        value: 7_000_000_000_000,
        asset_id: 0,
        spend_pk: u64s(crate::shield::key::derive(&h, sk_a).spend_pk),
        blinding: [11, 22, 33, 44],
    };
    let b = Note {
        value: 3_000_000_000_000,
        asset_id: 0,
        spend_pk: u64s(crate::shield::key::derive(&h, sk_b).spend_pk),
        blinding: [55, 66, 77, 88],
    };
    let zero_a = Note {
        value: 0,
        asset_id: 0,
        spend_pk: [21, 22, 23, 24],
        blinding: [25, 26, 27, 28],
    };
    let zero_b = Note {
        value: 0,
        asset_id: 0,
        spend_pk: [29, 30, 31, 32],
        blinding: [33, 34, 35, 36],
    };

    let mut t = PoolTree::with_depth(h.clone(), DEPTH);
    for filler in [101u64, 202, 303] {
        t.insert([Fp::from_u64(filler); RATE]);
    }
    let ia = t.insert(commitment_of(&a));
    let ib = t.insert(commitment_of(&b));
    t.insert([Fp::from_u64(404); RATE]);
    let open_a = Witnessed {
        leaf_index: ia,
        siblings: t.path(ia).0,
    };
    let open_b = Witnessed {
        leaf_index: ib,
        siblings: t.path(ib).0,
    };

    join_split_with_paths(
        DEPTH,
        [Spend { note: &a, sk: sk_a }, Spend { note: &b, sk: sk_b }],
        [&open_a, &open_b],
        t.root(),
        [&zero_a, &zero_b],
        10_000_000_000_000,
        0,
        Break::None,
        Settle {
            not_before: 0,
            clearing_price: 2_500_000,
            recipient: address_from_u64(0xDEAD_BEEF),
            fee_recipient: [0; 20],
        },
        None,
    )
}
