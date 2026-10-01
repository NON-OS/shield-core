// NONOS Operating System (AGPL-3.0-or-later)
//! A wallet holding one note can pay, and the bit that lets it cannot be used
//! to skip proving a real note is in the pool.
//!
//! A payment is always two inputs and two outputs, so a one note wallet pays
//! with a dummy beside its note. The circuit required membership for both legs,
//! so that wallet could not pay until it absorbed again, which is a pattern an
//! observer reads off the chain. The live gate makes the membership equality
//! conditional on a bit and makes the bit cost value.

use super::depth::MINIMAL;
use super::fixture::{owned, plain, secret};
use super::satisfies::satisfies;
use crate::shield::join::{address_from_u64, join_split_at, JoinSplit, Settle, Spend};
use crate::shield::key::Break;

/// One real note worth 1000 and a second input the caller sizes. The outputs
/// absorb whatever the second is worth, so nothing leaves publicly, no fee is
/// paid, and the sum closes at either size. That matters: the control case has
/// to differ from the forgery in the bit alone.
///
/// The second input is owned by the same wallet,
/// because a dummy is a note the payer holds rather than a note from nowhere:
/// the key hierarchy binds every input's committed spend key to the secret that
/// signs it, dummy or not.
fn spend_beside(second_value: u64, brk: Break) -> JoinSplit {
    let sks = [secret(1), secret(2)];
    let real = owned(sks[0], 0, 1000);
    let second = owned(sks[1], 0, second_value);
    let outs = [plain(20, 700 + second_value), plain(30, 300)];
    join_split_at(
        MINIMAL,
        [
            Spend {
                note: &real,
                sk: sks[0],
            },
            Spend {
                note: &second,
                sk: sks[1],
            },
        ],
        [&outs[0], &outs[1]],
        0,
        0,
        brk,
        Settle {
            not_before: 0,
            clearing_price: 0,
            recipient: address_from_u64(0),
            fee_recipient: [0; 20],
        },
        None,
    )
}

/// The payment a one note wallet makes: one real input and one dummy. This is
/// the case the circuit could not express before the gate, so a wallet down to
/// its last note had to absorb before it could pay.
#[test]
fn a_wallet_with_one_note_can_pay() {
    let js = spend_beside(0, Break::None);
    assert!(
        satisfies(&js.wired, &js.witness),
        "a spend with one real input and one dummy did not satisfy"
    );
}

/// The forgery the gate exists to refuse. A dead input skips its membership
/// proof, so the only thing a dead bit is worth is declaring a note that
/// carries value dead and spending what the pool never held. The gate's second
/// constraint refuses it: a dead input must be worth zero.
#[test]
fn a_dead_input_cannot_carry_value() {
    let js = spend_beside(500, Break::DeadCarrier);
    assert!(
        !satisfies(&js.wired, &js.witness),
        "an input carrying value was accepted with its live bit cleared"
    );
}

/// And the same input declared live is accepted, so the gate refuses the bit
/// rather than the note. Without this the test above would pass for the wrong
/// reason, on a spend that was broken some other way.
#[test]
fn the_same_input_declared_live_is_accepted() {
    let js = spend_beside(500, Break::None);
    assert!(
        satisfies(&js.wired, &js.witness),
        "a live input carrying value was refused, so the forgery proves nothing"
    );
}

/// A second input worth p is zero in the field, so it passes as a dummy and
/// skips its membership, but its limbs sum to p as an integer. Every value is
/// bounded below p - 1, so the room of its high limb is negative and the range
/// region refuses it.
#[test]
fn a_dummy_worth_p_is_refused() {
    let js = spend_beside(crate::crypto::stark::field::P, Break::None);
    assert!(
        !satisfies(&js.wired, &js.witness),
        "an input worth p passed as a dummy and carried p into the outputs"
    );
}
