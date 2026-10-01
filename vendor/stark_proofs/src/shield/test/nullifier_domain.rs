// NONOS Operating System (AGPL-3.0-or-later)
//! One note retires under one nullifier, whatever the prover absorbs to derive
//! its nullifier key.
//!
//! The key hierarchy is four compressions and the first two absorb domain
//! constants. Those constants ride the trace as witness cells in the production
//! form, so they are the prover's to choose unless a class holds them. The
//! spend key is held from the other side: it must equal the word the note
//! committed to, and hitting a fixed digest with a chosen absorbed word is a
//! preimage. The nullifier key is held from neither side. A different word
//! there is a different key, a different chain, and a different nullifier over
//! a note that is genuinely owned and genuinely a member, which is that note
//! spent twice.

use super::depth::MINIMAL;
use super::fixture::{owned, plain, secret};
use super::satisfies::satisfies;
use crate::shield::join::{address_from_u64, join_split_at, JoinSplit, Settle, Spend};
use crate::shield::key::Break;

fn spend(brk: Break) -> JoinSplit {
    spend_beside(500, brk)
}

fn spend_beside(second_value: u64, brk: Break) -> JoinSplit {
    let sks = [secret(1), secret(2)];
    let notes = [owned(sks[0], 0, 1000), owned(sks[1], 0, second_value)];
    let outs = [plain(20, 700 + second_value), plain(30, 300)];
    join_split_at(
        MINIMAL,
        [
            Spend {
                note: &notes[0],
                sk: sks[0],
            },
            Spend {
                note: &notes[1],
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

#[test]
fn the_honest_derivation_is_accepted() {
    let js = spend(Break::None);
    assert!(
        satisfies(&js.wired, &js.witness),
        "the honest key hierarchy did not satisfy"
    );
}

/// The double spend. Everything the circuit checks about this witness is true:
/// the note is in the pool, the secret derives the committed spend key, the
/// position is the authenticated one. The nullifier published is not the one
/// this note has. A prover who can pick the absorbed word picks a fresh one per
/// payment and spends the same note until it is empty, and the pool cannot tell
/// because every nullifier it sees is new.
#[test]
fn a_nullifier_key_derived_under_another_word_is_refused() {
    let js = spend(Break::ForeignDomain);
    assert!(
        !satisfies(&js.wired, &js.witness),
        "a nullifier key derived under a word that is not the domain constant was accepted"
    );
}

/// The other half, and the one the pool depends on. A payment's two nullifiers
/// are both burned and the pool cannot see which input was a dummy, so a dummy
/// whose nullifier is shaped like a note's is a payment that can retire a note
/// nobody spent. The dead lane is what separates the two spaces, and the gate
/// holds it to the liveness the value already decided.
#[test]
fn a_dummy_cannot_hash_its_nullifier_as_a_note_does() {
    let js = spend_beside(0, Break::LiveDeadLane);
    assert!(
        !satisfies(&js.wired, &js.witness),
        "a dummy retired a nullifier hashed under the live word"
    );
}

/// And the same payment with the lane the value calls for is accepted, so the
/// refusal above is the lane and not the dummy.
#[test]
fn the_same_dummy_with_its_own_lane_is_accepted() {
    let js = spend_beside(0, Break::None);
    assert!(
        satisfies(&js.wired, &js.witness),
        "a dummy under the dead word did not satisfy"
    );
}
