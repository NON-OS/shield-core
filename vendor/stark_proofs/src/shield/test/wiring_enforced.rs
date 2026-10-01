// NONOS Operating System (AGPL-3.0-or-later)
//! Every binding the shipped circuit emits is one the wiring enforces.
//!
//! A binding is a class of cells the permutation forces equal, and it holds
//! exactly when its cells land on one cycle of the group carrying them. Laying
//! two classes over a shared cell rewrites the first's cycle and can drop a cell
//! to a fixed point, which loses that binding while every other binding still
//! holds and the proof still verifies. That is how a second input's membership
//! came to be unheld on the artifact that settled.
//!
//! `wire_pack::groups_enforce` was written for exactly this and checks the built
//! groups rather than a sufficient precondition on the raw classes. It had three
//! unit tests over three toy cells and was never pointed at the shipped circuit:
//! the call that would have done it was a `debug_assert!`, and this crate is
//! built and tested under `--release` in ci.yml, soundness.yml, the release tier
//! and every emitter, so it ran nowhere. The gadget was correct and inert, which
//! is the same shape as the half-selector bound to the leaf instead of the half.
//!
//! These two say the check runs over something and that it bites.

use super::depth::{DEPLOYED, MINIMAL};
use super::scenario::balanced_parts_at;
use crate::shield::batch::{assemble, assemble_with_extra_classes};
use crate::shield::key::Break;
use crate::shield::wire_class::tie;
use crate::shield::wire_pack::{groups_enforce, packed_groups, CAP};

/// What the deployed join split emits, measured rather than guessed.
///
/// Pinned rather than floored. A binding that stops being emitted is the
/// failure this file exists for, and it leaves every remaining binding holding
/// and every other test green, so the only thing that can report it is the
/// count. A change that adds or removes one is welcome and moves this number
/// with the run that measured it, which is the arrangement `inner_cost` uses
/// for the term count and for the same reason.
///
/// The nullifier domain pinning adds one class per key region, and the range
/// region adds nineteen: six legs times a low limb, a high limb and a room,
/// and the carry. The claim build adds two: words 36 and 37 tied to the
/// balance region's running sums after the input legs.
const CLASSES: usize = if cfg!(feature = "claim") { 219 } else { 217 };

/// The shipped join split's bindings all hold.
#[test]
fn every_binding_the_shipped_circuit_emits_is_enforced() {
    let b = assemble(alloc::vec![balanced_parts_at(DEPLOYED, Break::None)]);
    assert_eq!(
        b.classes.len(),
        CLASSES,
        "the deployed join split emits a different number of bindings than it \
         did. More is a binding added; fewer is a binding that stopped being \
         emitted, which leaves the rest holding and every other gate green. Say \
         which and move the constant."
    );
    let groups = packed_groups(b.span, &b.classes, CAP);
    assert!(
        groups_enforce(&groups, &b.classes),
        "a binding class of the deployed join split is not on one cycle of its \
         group, so the cells it names are not forced equal"
    );
}

/// The same check, refusing a circuit whose wiring drops a binding.
///
/// Three cells tied pairwise are one equal set, and laying the three pairs in
/// sequence rotates the first out to a fixed point: the last pair, redundant
/// given the other two, rewrites the cycle and leaves that cell bound to
/// nothing. The cells are in the padding tail of column zero, so nothing the
/// circuit binds is disturbed and the only thing under test is whether the
/// assembly refuses a class list its groups do not enforce.
///
/// The panic has to come from the assembly rather than from this test, which is
/// why it goes in through `assemble_with_extra_classes` instead of calling
/// `groups_enforce` here: what is being gated is that the shipped path checks,
/// not that the checker works.
/// At the minimal depth, because what is under test is the assembly's refusal
/// and not the pool's shape, and this builds the circuit twice.
#[test]
#[should_panic(expected = "a binding class is not enforced by its group")]
fn the_assembly_refuses_a_binding_its_wiring_would_drop() {
    let probe = assemble(alloc::vec![balanced_parts_at(MINIMAL, Break::None)]);
    let (x, y, z) = (probe.span - 3, probe.span - 2, probe.span - 1);
    let extra = alloc::vec![
        tie(&[(x, 0), (y, 0)]),
        tie(&[(y, 0), (z, 0)]),
        tie(&[(x, 0), (z, 0)]),
    ];
    let _ =
        assemble_with_extra_classes(alloc::vec![balanced_parts_at(MINIMAL, Break::None)], extra);
}
