// NONOS Operating System (AGPL-3.0-or-later)
//! The half of a pair leaf the quotient reads is a bit, and it is the bit the
//! index names.
//!
//! THREAT 6a shares a FRI leaf between a value and its fold partner, which is
//! what makes one path per layer possible instead of one per opening. The cost
//! is that the leaf holds two extension values and something has to say which
//! the quotient consumes. A fixed lane is not an answer, because the answer
//! depends on which half of the domain the query landed in.
//!
//! So the region witnesses the index's top bit and the selected pair, and the
//! assembly binds that bit to the same scalar every other opening is bound to.
//! These gates hold the region's own half of that: the bit is a bit, and the
//! selected value is the half it names. The binding to the scalar is the
//! assembly's and is gated where the assembly is.
//!
//! Without both, a prover picks which committed value feeds the quotient, which
//! is not a choice a prover may have.

use crate::crypto::stark::air::{Air, AirExt, MultiMembership, Opening, Poseidon, RATE};
use crate::crypto::stark::field::{Fp, Fp2};
use crate::witness_satisfies::satisfies;
use alloc::vec::Vec;

const LOG_ROUNDS: u32 = 2;

fn hasher() -> Poseidon {
    Poseidon::new(LOG_ROUNDS, [Fp::ZERO; RATE])
}

/// One opening whose leaf is a pair: two extension values packed as
/// `[a.c0, a.c1, b.c0, b.c1]`, the shape a shared FRI leaf commits.
fn pair_opening(h: &Poseidon) -> Opening {
    let leaf: [Fp; RATE] = [
        Fp::from_u64(11),
        Fp::from_u64(22),
        Fp::from_u64(33),
        Fp::from_u64(44),
    ];
    let sib = [Fp::from_u64(7); RATE];
    let mut state = [Fp::ZERO; 2 * RATE];
    state[..RATE].copy_from_slice(&leaf);
    state[RATE..].copy_from_slice(&sib);
    let root = h.compress(&leaf, &sib);
    Opening {
        leaf,
        root,
        siblings: alloc::vec![sib],
        directions: alloc::vec![false],
    }
}

fn region(top: bool) -> (MultiMembership, Vec<Fp>) {
    let h = hasher();
    let r = MultiMembership::new_witness_pin0_half(
        h.clone(),
        LOG_ROUNDS,
        alloc::vec![pair_opening(&h)],
        alloc::vec![Some(top)],
    );
    let t = r.trace();
    (r, t)
}

/// The honest region satisfies at either half, and the selected value is the
/// half the bit names rather than a fixed lane.
#[test]
fn the_selected_value_is_the_half_the_bit_names() {
    for top in [false, true] {
        let (r, trace) = region(top);
        assert!(
            satisfies(&r, &trace),
            "a pair leaf region with top bit {top} did not satisfy its own constraints"
        );
        let lo = if top { RATE / 2 } else { 0 };
        for j in 0..RATE / 2 {
            assert_eq!(
                trace[r.sel_col() + j],
                trace[r.leaf_col() + lo + j],
                "the selected lane {j} is not the half the bit names at top {top}"
            );
        }
        assert_eq!(
            trace[r.half_col()],
            if top { Fp::ONE } else { Fp::ZERO },
            "the witnessed bit is not the index's top bit"
        );
    }
}

/// The bit is a bit. Anything between the two halves is a blend of two
/// committed values and is not one of them, which is the forgery the
/// booleanity constraint exists to refuse.
#[test]
fn a_selector_between_the_halves_is_refused() {
    let (r, mut trace) = region(false);
    trace[r.half_col()] = Fp::from_u64(2);
    assert!(
        !satisfies(&r, &trace),
        "a selector that is neither zero nor one was accepted"
    );
}

/// And the selected value has to be the half, not a value of the prover's
/// choosing. This keeps the bit honest and moves the pair instead.
#[test]
fn a_selected_value_that_is_neither_half_is_refused() {
    let (r, mut trace) = region(false);
    trace[r.sel_col()] = trace[r.sel_col()] + Fp::ONE;
    assert!(
        !satisfies(&r, &trace),
        "a selected value that is neither half of the leaf was accepted"
    );
}

/// The bit flipped without the pair moving takes the quotient to the other
/// committed value, which is the whole attack: both values are in the leaf and
/// both authenticate under the same root.
#[test]
fn flipping_the_bit_alone_is_refused() {
    let (r, mut trace) = region(false);
    trace[r.half_col()] = Fp::ONE;
    assert!(
        !satisfies(&r, &trace),
        "the selector moved to the other half while the selected value stayed"
    );
}

/// An opening that binds the whole leaf gets the whole leaf.
///
/// A FRI layer's leaf holds a value and its fold partner and the fold reads
/// both, so that opening wants the pair and a selector there would hand the
/// fold one of the two values it needs. The set is mixed on purpose and this
/// holds that it stays mixed.
#[test]
fn an_opening_that_binds_the_whole_leaf_is_not_given_a_half() {
    let h = hasher();
    let r = MultiMembership::new_witness_pin0_half(
        h.clone(),
        LOG_ROUNDS,
        alloc::vec![pair_opening(&h), pair_opening(&h)],
        alloc::vec![None, Some(true)],
    );
    let cells = r.opened_cells();
    assert_eq!(cells.len(), 2, "two openings, two opened cells");
    assert_eq!(
        cells[0].1,
        r.leaf_col(),
        "the opening that binds the whole leaf was given a half"
    );
    assert_eq!(
        cells[1].1,
        r.sel_col(),
        "the opening that names a half was given the whole leaf"
    );
    assert!(
        crate::witness_satisfies::satisfies(&r, &r.trace()),
        "a mixed set does not satisfy its own constraints"
    );
}

/// The cell the assembly binds the quotient to is the selected pair, not the
/// leaf.
///
/// This is the one that makes the gadget do anything. Binding the leaf binds its
/// first lane, which is the low half's `c0` whatever the index says, and that is
/// the fixed lane the whole selector exists to remove. Every constraint above
/// still holds in that case and every gate above still passes, so nothing except
/// this one would have said the gadget was inert.
#[test]
fn the_assembly_binds_the_selected_pair_and_not_the_leaf() {
    for top in [false, true] {
        let (r, _) = region(top);
        let cells = r.opened_cells();
        assert_eq!(cells.len(), 1, "one opening, one opened cell");
        assert_eq!(
            cells[0].1,
            r.sel_col(),
            "the fold is bound to the leaf rather than to the half the index names"
        );
        assert_ne!(
            cells[0].1,
            r.leaf_col(),
            "the fold is bound to the leaf's first lane, which is a fixed lane"
        );
    }
}

/// The region reports the columns and constraints it actually carries, so an
/// assembly that lays regions out by these numbers does not silently overlap
/// the next one.
#[test]
fn the_region_accounts_for_its_own_columns() {
    let (r, trace) = region(false);
    let w = Air::trace_width(&r);
    assert_eq!(r.sel_col() + RATE / 2, w, "the selected pair is not the last column");
    assert_eq!(trace.len() % w, 0, "the trace is not a whole number of rows");
    let n = AirExt::transition_ext(
        &r,
        &alloc::vec![Fp2::ZERO; 2 * w],
        &alloc::vec![Fp2::ZERO; 64],
    )
    .len();
    assert_eq!(n, Air::num_transition(&r), "the reported constraint count is wrong");
}
