// NONOS Operating System (AGPL-3.0-or-later)
//! Conservation holds modulo p, and p is below 2^64, so an honest u64 amount
//! of p - K is -K in the field. Two outputs worth a + b + K and p - K balance
//! against inputs worth a + b. A circuit that bounds values only by their
//! u64 width accepts that transfer, and spending the first output later takes
//! K from the pool.

use super::live::*;
use crate::crypto::stark::field::P;
use crate::shield::join::{address_from_u64, join_split_with_paths};
use crate::shield::join::{Settle, Spend, Witnessed};
use crate::shield::key::Break;
use crate::shield::note::Note;
use crate::witness_satisfies_public;

/// One ether of value the transfer creates.
const K: u64 = 1_000_000_000_000_000_000;

/// A transfer whose outputs sum to its inputs only modulo p is refused.
#[test]
fn a_transfer_that_balances_only_modulo_p_is_refused() {
    let a = note_of(A_SK, A_BLINDING, NOTE_VALUE);
    let b = note_of(B_SK, B_BLINDING, NOTE_VALUE);
    let rich = Note {
        value: 2 * NOTE_VALUE + K,
        asset_id: 0,
        spend_pk: [0xA1, 0xA2, 0xA3, 0xA4],
        blinding: [0xB1, 0xB2, 0xB3, 0xB4],
    };
    let negative = Note {
        value: P - K,
        asset_id: 0,
        spend_pk: [0xC1, 0xC2, 0xC3, 0xC4],
        blinding: [0xD1, 0xD2, 0xD3, 0xD4],
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
        [&rich, &negative],
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
        "a transfer created {K} wei by wrapping the field"
    );
}
