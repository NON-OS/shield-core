// NONOS Operating System (AGPL-3.0-or-later)

//! The join-split's circuit from its public words alone.
//!
//! A relayer folds a wallet's inner proof into the outer the chain verifies,
//! and to do that it holds the inner AIR: the outer recomputes every inner
//! constraint at z and pins every inner boundary. That AIR is built from a
//! witness, and the wallet's witness is the one thing a relayer must never
//! see. What the circuit depends on, though, is the statement: the depth and
//! the thirty six public words. The secrets shape the trace and nothing else.
//!
//! So the circuit is rebuilt here over a witness nobody owns, with the publics
//! region built from the wallet's intent rather than derived from the dummy,
//! and `shield::test::shape` holds the result equal, method by method, to the
//! circuit the wallet proved. A relayer that holds this and the wallet's
//! proof bytes can make the outer, and learns what the chain learns.

use super::parts::intent_parts_anchored;
use super::stack::{Anchor, AssocAnchor};
use super::{address_from_u64, Settle, Spend, Witnessed};
use crate::crypto::stark::air::{Publics, ShieldRegion, WiredMultiGen, RATE};
use crate::crypto::stark::field::Fp;
use crate::shield::batch::assemble;
use crate::shield::key::Break;
use crate::shield::note::Note;

/// Where the intent keeps the words the shape reads.
const NOTE_ROOT: usize = 0;
const ASSOC_ROOT: usize = 4;
const PUBLIC_AMOUNT: usize = 24;
const FEE: usize = 25;
const ASSET: usize = 26;
/// Two roots, two nullifiers, two commitments, the amount, the fee, the
/// asset, the price, the recipient and the fee recipient: thirty six words,
/// and a thirty seventh, the earliest settlement time, in the `not_before`
/// build.
pub const INTENT_WORDS: usize = super::publics::WORDS;

/// The circuit a wallet proved, from its intent and the tree depth.
///
/// The dummy witness balances the statement so no region is asked for a
/// trace it cannot lay out, and carries the statement's asset; every other
/// value in it is a constant nobody holds a key for. None of it survives into
/// the AIR, which is the claim the shape gate checks.
pub fn join_split_shape(depth: usize, intent: &[Fp]) -> WiredMultiGen {
    assert_eq!(
        intent.len(),
        INTENT_WORDS,
        "an intent is INTENT_WORDS words"
    );
    let quad = |at: usize| -> [Fp; RATE] { core::array::from_fn(|i| intent[at + i]) };
    let public_amount = intent[PUBLIC_AMOUNT].to_u64();
    let fee = intent[FEE].to_u64();
    let asset_id = intent[ASSET].to_u64();

    let limbs = |k: u64| -> [u64; RATE] { core::array::from_fn(|i| 1 + k * 8 + i as u64) };
    let sk = |k: u64| -> [Fp; RATE] { limbs(k).map(Fp::from_u64) };
    let note = |k: u64, value: u64| Note {
        value,
        asset_id,
        spend_pk: limbs(k),
        blinding: limbs(k + 1),
    };
    let inputs = [note(0, public_amount + fee), note(2, 0)];
    let outputs = [note(4, 0), note(6, 0)];
    let opening = Witnessed {
        leaf_index: 0,
        siblings: alloc::vec![[Fp::ZERO; RATE]; depth],
    };

    let mut p = intent_parts_anchored(
        [
            Spend {
                note: &inputs[0],
                sk: sk(8),
            },
            Spend {
                note: &inputs[1],
                sk: sk(9),
            },
        ],
        [&outputs[0], &outputs[1]],
        public_amount,
        fee,
        Break::None,
        Settle {
            not_before: intent
                .get(super::publics::NOT_BEFORE)
                .map_or(0, |w| w.to_u64()),
            clearing_price: 0,
            recipient: address_from_u64(0),
            fee_recipient: [0; 20],
        },
        None,
        depth,
        Anchor::Published {
            openings: [&opening, &opening],
            root: quad(NOTE_ROOT),
            assoc: Some(AssocAnchor {
                openings: [&opening, &opening],
                root: quad(ASSOC_ROOT),
            }),
        },
    );

    /*
     * The publics region is the one region whose boundary is the statement
     * rather than the circuit. Built from the wallet's words, not the dummy's;
     * everything else in the parts is shape.
     */
    let last = p
        .regions
        .iter()
        .position(|r| matches!(r, ShieldRegion::Publics(_)))
        .unwrap_or_else(|| unreachable!("every intent stacks one publics region"));
    let publics = Publics {
        log_t: 6,
        words: intent.to_vec(),
    };
    p.traces[last] = publics.trace();
    p.regions[last] = ShieldRegion::Publics(publics);
    p.intent = intent.to_vec();
    assemble(alloc::vec![p]).wired
}
