// NONOS Operating System (AGPL-3.0-or-later)
//! The settlement outer as a generic inner: the precondition a wrap rests on
//! that was not in the list.
//!
//! A recursion verifies its inner by recomputing that inner's transition over
//! the tower. The outer held its regions as trait objects, which offer a
//! transition over one field only, so no recursion could be built over it
//! whatever else was ready. `assemble_over_gen` keeps the same regions by name
//! beside the boxes, and these two gates say what that buys and what it costs.
//!
//! The first is the seam. The boxed engine and the named list are two views
//! of one allocation, and the prover walks one while a wrap would walk the
//! other, so a region wired into the list at the wrong index would let the
//! prover prove one circuit and the wrap verify another with nothing failing.
//! Evaluating both views on a real window of the real witness and requiring
//! them equal is the only check that spans that seam.
//!
//! The second is the number every plan is being made against: the width of a
//! wrap's compose region, read off the outer's own shape through the compose
//! gadget's own slot layout rather than a model of it. It is held to reproduce
//! the emitted 590 on the outer's own inner first, so a wrong slot arithmetic
//! cannot produce a plausible wrap figure.

use crate::crypto::stark::air::{
    periodic_root_poseidon, stark_prove_poseidon_pre_rounds, Air, AirExt, GenericTransition,
    Permuted, Poseidon, Slots,
};
use crate::crypto::stark::field::{Fp, Fp2};
use crate::recursion_assembly::anchors::Anchors;
use crate::recursion_assembly::inner::{hasher, pack_air, shield_join_split, EXTRA, GRIND};
use crate::recursion_assembly::point::Point;
use crate::recursion_assembly::{assemble_over_gen_form, AssemblyGen, ComposeForm, Tamper};
use crate::crypto::stark::air::WiredMultiGen;
use alloc::vec::Vec;

/// Two queries of the outer. Every region kind is present at a cap of two, so
/// the seam under test is the same seam; what shrinks is the rows.
const CAP: usize = 2;

/// The shared kinds precede the first per-query block, which starts at the
/// DEEP quotient.
fn shared_kinds(bodies: &[(&str, &str)]) -> usize {
    bodies.iter().position(|b| b.0 == "deep").expect("a per-query block")
}

/// With the anchors collapsed: the shape a wrap is priced against, which is
/// not yet the shape a verifier is deployed against. `anchors::DEPLOYED` says
/// which, and flips after the first settled spend.
pub(crate) fn typed_outer(cap: usize) -> AssemblyGen<WiredMultiGen> {
    crate::wrap::typed_outer(&hasher(), cap)
}

fn lift(v: &[Fp]) -> Vec<Fp2> {
    v.iter().map(|x| Fp2::from_base(*x)).collect()
}

/// The compose region a recursion over `a` would carry, in base columns, by
/// the gadget's own slot layout. `ch` is the challenge count of `a`'s copy
/// constraint, two once drawn and zero for an AIR without one.
fn compose_width<A: Air>(a: &A, ch: usize) -> usize {
    let s = Slots {
        w: a.window_size() * a.trace_width(),
        p: a.periodic_columns().len(),
        ch,
        nt: a.num_transition(),
        b: a.boundary().len(),
        k: a.log_trace_len() as usize,
        strip: true,
        pw: 0,
    };
    2 * s.total()
}

/// The named list recomputes exactly what the boxed engine proves.
#[test]
#[ignore]
fn the_typed_outer_recomputes_what_the_boxed_outer_proves() {
    let mut asm = typed_outer(CAP);
    asm.gen.set_challenges(Fp::from_u64(3), Fp::from_u64(5));
    let w = Air::trace_width(&asm.gen);
    let window = Air::window_size(&asm.gen);
    let pcols = asm.gen.periodic_columns();

    // The compose region's first row, where the body that recomputes the
    // inner fires, and row zero. A seam that only agrees on padding agrees on
    // nothing.
    for &r in &[asm.region_offsets[1], 0usize] {
        let win = lift(&asm.witness[r * w..(r + window) * w]);
        let per: Vec<Fp2> = pcols.iter().map(|c| Fp2::from_base(c[r])).collect();
        let boxed = asm.gen.transition_ext(&win, &per);
        let typed = asm.gen.transition_gen::<Fp2>(&win, &per);
        assert_eq!(boxed.len(), typed.len(), "row {r}: lane counts differ");
        assert_eq!(boxed.len(), Air::num_transition(&asm.gen));
        for (i, (b, t)) in boxed.iter().zip(&typed).enumerate() {
            assert!(
                b == t,
                "row {r} lane {i}: the boxed engine says {b:?} and the named list {t:?}"
            );
        }
    }
}

/// The slot layout reproduces the emitted compose width on the outer's own
/// inner, and then says what a wrap's would be.
#[test]
#[ignore]
fn the_wraps_compose_width_is_read_off_the_real_outer() {
    let inner = crate::shield_deployed_wired();
    let over_inner = compose_width(&inner, 2);
    assert_eq!(
        over_inner, 590,
        "the slot layout over the deployed inner must give the emitted region_width"
    );

    let asm = typed_outer(usize::MAX);
    let over_outer = compose_width(&asm.gen, 2);
    std::println!(
        "wrap compose region over the outer: {over_outer} base columns \
         (outer width {}, periodic {}, transitions {}, boundaries {}, log rows {})",
        Air::trace_width(&asm.gen),
        asm.gen.periodic_columns().len(),
        Air::num_transition(&asm.gen),
        asm.gen.boundary().len(),
        Air::log_trace_len(&asm.gen)
    );
    assert!(over_outer > over_inner, "a wrap cannot be narrower than the outer it verifies");
}

/// The wrap exists as a circuit: the typed outer is proved under Poseidon,
/// packed as an inner the way a join-split is, and a recursion is assembled
/// over it. Its shape is printed off the assembled object, which is the first
/// wrap figure that is neither a model nor a slot count but the circuit.
///
/// At a cap of two on both layers, so the outer is small and the wrap's rows
/// are few; every region kind of the wrap is present and its width is the
/// width, since width is per kind and not per query.
#[test]
#[ignore]
fn the_wrap_assembles_over_the_typed_outer() {
    let h: Poseidon = hasher();
    let mut asm = typed_outer(CAP);
    let publics = asm.publics.clone();
    // At the deployment grind and blowup, because the FRI side of the assembly
    // checks the inner's proof-of-work against the deployment constant; eight
    // queries, because the width under measurement is per kind and not per
    // query.
    let root = periodic_root_poseidon(&asm.gen, EXTRA, &h);
    let mut witness = core::mem::take(&mut asm.witness);
    let Some((rounds, air)) =
        stark_prove_poseidon_pre_rounds(asm.gen, &mut witness, 8, GRIND, EXTRA, &h, &publics, &[])
    else {
        panic!("the typed outer carries no permutation columns above its regions");
    };
    drop(witness);
    let inner = pack_air(&h, air, rounds, publics, root, EXTRA, GRIND);

    let wrap = crate::recursion_assembly::assemble_over_gen(
        &h,
        inner,
        Tamper::None,
        CAP,
        Point::emit_wiring(),
        Anchors::Collapsed,
    );
    let w = Air::trace_width(&wrap.gen);
    let p = wrap.gen.periodic_columns().len();
    std::println!(
        "the wrap, assembled: width {w}, region_width {}, transitions {}, boundaries {}, \
         periodic {p}, log rows {}, n_deep_terms {}",
        Permuted::region_width(&wrap.gen),
        Air::num_transition(&wrap.gen),
        wrap.gen.boundary().len(),
        Air::log_trace_len(&wrap.gen),
        2 * w + p + 1
    );

    /*
     * Where the rows are, by kind. The wrap's row count is what decides its
     * rate, and the rate is what decides one transaction: at 2^20 rows the
     * domain at rate 1/4096 is 2^36 against a ceiling of 2^27. Four shared
     * kinds come first, then one block of eight per outer query, in the order
     * `kind_bodies` names them.
     */
    let shapes = wrap.gen.wired().region_shapes();
    let shared = shared_kinds(&wrap.kind_bodies);
    let per_q = wrap.kind_bodies.len() - shared;
    let mut rows_by_kind = alloc::vec![0usize; wrap.kind_bodies.len()];
    let mut width_by_kind = alloc::vec![0usize; wrap.kind_bodies.len()];
    for (i, &(width, rows)) in shapes.iter().enumerate() {
        let k = if i < shared { i } else { shared + (i - shared) % per_q };
        rows_by_kind[k] += rows;
        width_by_kind[k] = width;
    }
    let total: usize = rows_by_kind.iter().sum();
    for (k, (body, role)) in wrap.kind_bodies.iter().enumerate() {
        std::println!(
            "  rows {:>9}  {:5.1}%  width {:>5}  {body}/{role}",
            rows_by_kind[k],
            100.0 * rows_by_kind[k] as f64 / total as f64,
            width_by_kind[k]
        );
    }
    std::println!("  rows {total:>9} total over {} regions, padded to 2^{}", shapes.len(), Air::log_trace_len(&wrap.gen));
    assert!(w > 0 && Air::num_transition(&wrap.gen) > 0);
}

/// The same assembly one layer down and in seconds: the settlement outer over
/// the shield inner in the program form. The code path is the wrap's; what
/// differs is the inner. A failure here names the region and the lane.
#[test]
fn the_outer_assembles_as_a_program_over_the_shield_inner() {
    let h: Poseidon = hasher();
    let outer = assemble_over_gen_form(
        &h,
        shield_join_split(&h),
        Tamper::None,
        CAP,
        Point::emit_wiring(),
        Anchors::Collapsed,
        ComposeForm::Program,
    );
    let bad = crate::witness_satisfies::violations(&outer.gen, &outer.witness, 12);
    if !bad.is_empty() {
        let offs = &outer.region_offsets;
        let shared = shared_kinds(&outer.kind_bodies);
        let per_q = outer.kind_bodies.len() - shared;
        for (row, lane) in &bad {
            let region = offs.iter().rposition(|&o| o <= *row).unwrap_or(0);
            let k = if region < shared { region } else { shared + (region - shared) % per_q };
            std::println!(
                "violation at row {row} lane {lane}: region {region} ({}/{}) local row {}",
                outer.kind_bodies[k].0,
                outer.kind_bodies[k].1,
                row - offs[region]
            );
        }
    }
    assert!(bad.is_empty(), "the program form over the shield inner does not satisfy: {bad:?}");
}

/// One outer circuit for every inner proof. The fold's final value used to be
/// pinned as a boundary, so the outer's AIR carried one inner proof's number
/// and a verifier generated from it accepted no other proof: a verifier per
/// proof. Two proofs of the deployed inner, different blinds and different
/// final polynomials, assemble into outers with the same boundaries, the
/// same periodic columns and the same width.
#[test]
#[ignore = "release tier: proves the deployed inner twice"]
fn the_outer_is_one_circuit_over_two_inner_proofs() {
    use crate::crypto::stark::air::RATE;
    use crate::recursion_assembly::inner::{hasher, shield_join_split_hidden};
    use crate::recursion_assembly::assemble_over;
    let h = hasher();
    let mut seeds = [[Fp::ZERO; RATE]; 2];
    seeds[0][0] = Fp::from_u64(11);
    seeds[1][0] = Fp::from_u64(29);
    let outers: alloc::vec::Vec<_> = seeds
        .iter()
        .map(|seed| {
            let inner = shield_join_split_hidden(&h, seed);
            assemble_over(&h, inner, Tamper::None, 2)
        })
        .collect();
    let (a, b) = (&outers[0].wired, &outers[1].wired);
    assert_eq!(a.trace_width(), b.trace_width(), "the width moved with the proof");
    assert_eq!(a.boundary(), b.boundary(), "a boundary carries one proof's value");
    assert_eq!(a.periodic_columns(), b.periodic_columns(), "a periodic column carries one proof's value");
}

/// What the settlement outer costs in each compose form, side by side. The
/// wrap went from 7,101 columns to 24 by recording its composition as a
/// program; the same question one layer down decides the settlement proof's
/// size and its proving time, because a fused trace pays its widest region
/// at every row and the evaluation domain follows the row count.
#[test]
#[ignore = "release tier: assembles the settlement outer twice"]
fn what_the_outer_costs_in_each_form() {
    let h: Poseidon = hasher();
    for form in [ComposeForm::Strip, ComposeForm::Program] {
        let asm = assemble_over_gen_form(
            &h,
            shield_join_split(&h),
            Tamper::None,
            usize::MAX,
            Point::emit_wiring(),
            Anchors::Collapsed,
            form,
        );
        let w = Air::trace_width(&asm.gen);
        let rows = 1usize << Air::log_trace_len(&asm.gen);
        let deg = Air::constraint_degree(&asm.gen);
        let per = asm.gen.periodic_columns().len();
        let bound = (deg * rows).next_power_of_two();
        let log_domain = (bound << 4).trailing_zeros();
        let shapes = asm.gen.wired().region_shapes();
        let used: usize = shapes.iter().map(|&(rw, rr)| rw * rr).sum();
        std::println!(
            "{form:?}: width {w}, periodic {per}, degree {deg}, rows {rows}, log_domain {log_domain}, \
             DEEP terms {}, cells {} of {} used ({:.1}%)",
            2 * w + per + 1,
            used,
            w * rows,
            100.0 * used as f64 / (w * rows) as f64
        );
    }
}
