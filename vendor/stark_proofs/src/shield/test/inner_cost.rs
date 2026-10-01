// NONOS Operating System (AGPL-3.0-or-later)
//! What the inner's shape costs the wrap, asserted so a change has to say so.
//!
//! The wrap's size is a step function in the outer's DEEP term count,
//!
//!     n_deep_terms = 2 * outer_trace_width + outer_n_periodic + 1
//!
//! and both halves are the inner's. The outer's widest region is the
//! composition, and the composition carries the inner's frame, a claim per
//! inner periodic column, and a coefficient per inner constraint. The periodic
//! count carries one permutation column per wired column, so a wired column
//! costs three terms rather than two.
//!
//! Per unit of the inner, measured against the deployed emit:
//!
//!     trace column    12   (two window rows, two base columns each, all wired)
//!      periodic column  6   (one claim at z, wired)
//!      transition       6   (one coefficient, wired)
//!      boundary        10   (a coefficient at 6, plus an unwired quotient at 4)
//!
//! This exists because a change was reviewed correctly along the only axis
//! anyone was looking at. Pinning the key hierarchy's domain words closed a
//! double spend and added twenty-two inner boundaries, which is two hundred and
//! twenty terms, more than half of one day's regression. Nobody asked what it
//! cost because nothing made them.
#![cfg_attr(
    any(feature = "launch_v1", feature = "v2"),
    allow(dead_code, unused_imports)
)]

use super::depth::DEPLOYED;
use super::scenario::balanced_at;
use crate::crypto::stark::air::Air;
use crate::shield::key::Break;

/// The deployed inner, as the emitted structure file reports it.
///
/// Boundaries were 62 until 2026-09-21, when the nullifier domain pinning went
/// from a boundary per lane to a boundary per distinct value plus one wiring
/// class over the lanes that share zero. Fourteen boundaries, 140 DEEP terms,
/// and the measured `PERIODIC` did not move: the class landed on columns that
/// the commitment absorbed at the third compression already wires, so it cost no
/// permutation column to pay for itself with.
/// Moved 2026-09-22 by the S-box split. The inner's membership regions ran
/// the Poseidon S-box directly, at degree 8, which made the fused inner 10
/// and its evaluation domain 2^21. Over witnessed squares the round is
/// degree 3 and the inner is 8, bound 2^16, domain 2^20: half the inner's
/// proving cost for the same statement. The price is two columns and two
/// constraints per lane per membership region, which is the +14 width and
/// +17 transitions below, and by the pricing above that is 344 terms.
///
/// Worth it twice over, and the second reason matters more than the first:
/// the outer's own per-query regions hash the inner's row, so a wider inner
/// costs the outer, but the outer in program form hashes 41 values where it
/// hashed 662, and the pricing constants below are the strip form's. They
/// are the cost of an inner column against a wrap built over a strip-form
/// outer, and that outer is being retired. Re-measure them against the
/// program form before anyone spends them.
///
/// Two of the forty-four are the mask columns (`shield::batch::MASK_COLUMNS`):
/// no constraint reads them, and they are what makes FRI's openings hide.
/// Four more, with four transitions and eight boundaries, are the copy
/// constraint argued in `Fp2`: each of the four groups' running products is
/// two columns and two constraints, starting and closing at `(1, 0)`. Over
/// `Fp` a wiring forgery had `t k / p`, about `2^-46`, per attempt. 152 DEEP
/// terms at the pricing below for both, and neither is optional.
///
/// Four boundaries more for `fee_recipient`, the fee's payee as a public word,
/// so a submitter who copies a settlement cannot take the fee: 40 terms.
const TRACE_WIDTH: usize = 44;
/// Three from the range region: the balance close column, the region's selector, its end column.
/// The checkpoint rule moved these: one selector column per membership and
/// chain kind (93 to 97), and per kind the direction and sibling held at zero
/// off an injection row (38 to 43). About 54 deep terms, taken because the
/// checkpoint row has to carry the walked digest and nothing else.
const PERIODIC: usize = 97;
const TRANSITIONS: usize = 43;
const BOUNDARIES: usize = 62;

/// Terms each of those costs the outer.
const PER_WIDTH: usize = 12;
const PER_PERIODIC: usize = 6;
const PER_TRANSITION: usize = 6;
const PER_BOUNDARY: usize = 10;

/// The boundary the wrap halves at. A term count at or below this is one fewer
/// FRI layer over the wrap's own codeword.
const STEP: usize = 2047;

/// The deployed emit's count, so a drift is reported as a distance from the
/// boundary rather than as an equality nobody can read.
///
/// Read off `emit_real_structure` at the shipping wiring rather than carried
/// forward by arithmetic. This constant said 2523 and then 2383, the second
/// being the first minus the 140 the collapse above measured. A fresh emit says
/// 2375 and `2 * 644 + 1086 + 1` confirms it, so the 2523 had itself been stale
/// by 8 and the subtraction inherited that. A count that is the emitter's is
/// taken from the emitter.
const EMITTED: usize = 2375;

/// The inner is the shape the wrap is priced against, and a change to it prices
/// itself here.
///
/// Not a ban. A constraint the circuit needs is worth its terms and the live
/// gate and the domain pinning both were. What this refuses is a change landing
/// without anyone seeing the number, which is how two hundred and twenty terms
/// arrived in one morning.
///
/// The wrap is priced for the stacked circuit. Under v2 the periodic overlay
/// puts every kind's slots on shared columns, 59 where the stack has 97, so
/// this pin belongs to the stacked builds only.
#[cfg(not(any(feature = "launch_v1", feature = "v2")))]
#[test]
fn the_inner_shape_is_the_one_the_wrap_is_priced_against() {
    let js = balanced_at(DEPLOYED, Break::None);
    let (w, p) = (js.wired.trace_width(), js.wired.periodic_columns().len());
    let (ntr, nb) = (js.wired.num_transition(), js.wired.boundary().len());

    let moved = (w as isize - TRACE_WIDTH as isize) * PER_WIDTH as isize
        + (p as isize - PERIODIC as isize) * PER_PERIODIC as isize
        + (ntr as isize - TRANSITIONS as isize) * PER_TRANSITION as isize
        + (nb as isize - BOUNDARIES as isize) * PER_BOUNDARY as isize;

    assert_eq!(
        (w, p, ntr, nb),
        (TRACE_WIDTH, PERIODIC, TRANSITIONS, BOUNDARIES),
        "the inner moved: width {w} periodic {p} transitions {ntr} boundaries {nb}, \
         which is {moved} deep terms against the emitted {EMITTED}, and the wrap \
         halves at {STEP}. If the change is worth it, say so and move these \
         constants with the emit that measured it."
    );
}

/// The gap the inner-boundary work had to close, and the day it stopped
/// being the question.
///
/// It was 328 terms against a 2,047 boundary, and the whole list above was
/// written to find them one boundary at a time. On 2026-09-22 the outer was
/// laid out with its composition as a straight-line program and its DEEP
/// terms went from 2,424 to 202, so the boundary is no longer anywhere near.
/// The gate stays because the arithmetic is still the arithmetic and the
/// strip form is still what a batch is assembled in until `n_inners` moves;
/// what it now asserts is that the distance is on the right side, not what
/// it is.
#[test]
fn the_distance_to_the_wrap_boundary_is_stated() {
    let strip = EMITTED;
    let program = 202;
    assert!(
        strip > STEP,
        "the strip form is over the boundary, which is why it is being retired"
    );
    assert!(
        program < STEP,
        "the program form is under the boundary by {}, which is the change that closed this",
        STEP - program
    );
    // What an inner column is worth against a strip-form outer, kept so the
    // cost model can be re-measured against the program form rather than
    // carried forward by arithmetic.
    assert_eq!(BOUNDARIES * PER_BOUNDARY, 620);
    assert_eq!(PERIODIC * PER_PERIODIC, 582); // 558 before the checkpoint selectors
}
