// NONOS Operating System (AGPL-3.0-or-later)

//! The recorded programs, laid out as the line region, satisfy that region's
//! constraints row by row, and the one that matters has every output at
//! zero on the real witness: the compose gadget over the outer, which is the
//! wrap's composition region in three columns.

use crate::crypto::stark::air::{Air, GenericTransition, LineEval, Poseidon};
use crate::crypto::stark::field::{Fp, Fp2};
use crate::wrap::Rec;
use crate::wrap_gen_tests::typed_outer;

fn stream(seed: u64) -> impl FnMut() -> Fp2 {
    let mut x = seed;
    move || {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let c0 = Fp::from_u64(x >> 1);
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        Fp2 { c0, c1: Fp::from_u64(x >> 1) }
    }
}

/// The transitions at a random point, recorded over the extension.
fn transitions_region() -> LineEval {
    let asm = typed_outer(2);
    let air = &asm.gen;
    let w = Air::window_size(air) * Air::trace_width(air);
    let n = Air::periodic_columns(air).len();
    let mut next = stream(0x11e_e7a1);
    let window: Vec<Fp2> = (0..w).map(|_| next()).collect();
    let periodic: Vec<Fp2> = (0..n).map(|_| next()).collect();
    Rec::<Fp2>::start();
    let win_r: Vec<Rec<Fp2>> = (0..w).map(|i| Rec::input(i, window[i])).collect();
    let per_r: Vec<Rec<Fp2>> = (0..n).map(|i| Rec::input(w + i, periodic[i])).collect();
    /*
     * The transition values at a random point are not zero and are not
     * meant to be: they are what the composition combines. Nothing is
     * pinned here; the claim is that the region enforces every step.
     */
    let _outs: Vec<Rec<Fp2>> = air.transition_gen_at::<Rec<Fp2>>(&win_r, &per_r, &[]);
    LineEval::new_ext(Rec::<Fp2>::take().program(&[]))
}

/// Every transition lane over every row, and every boundary; a row that
/// fails is named.
fn violations(air: &LineEval, trace: &[Fp]) -> Vec<(usize, usize)> {
    let rows = air.rows();
    let width = air.trace_width();
    let cols = air.periodic_columns();
    let mut bad = Vec::new();
    for r in 0..rows {
        let r1 = (r + 1) % rows;
        let mut window = Vec::with_capacity(2 * width);
        window.extend_from_slice(&trace[r * width..(r + 1) * width]);
        window.extend_from_slice(&trace[r1 * width..(r1 + 1) * width]);
        let per: Vec<Fp> = cols.iter().map(|c| c[r]).collect();
        for (lane, v) in air.transition(&window, &per).iter().enumerate() {
            if *v != Fp::ZERO {
                bad.push((r, lane));
            }
        }
    }
    for (col, row, expected) in air.boundary() {
        if trace[row * width + col] != expected {
            bad.push((row, width + col));
        }
    }
    bad
}

fn describe(name: &str, air: &LineEval) {
    println!(
        "{name}: {} steps in {} rows x {} columns, {} periodic, {} lanes, {} boundaries, {} classes",
        air.program().ops.len(),
        air.rows(),
        air.trace_width(),
        air.periodic_columns().len(),
        air.num_transition(),
        air.boundary().len(),
        air.classes().len()
    );
}

#[test]
fn the_program_region_is_satisfied_by_its_own_trace() {
    let air = transitions_region();
    let trace = air.trace();
    let bad = violations(&air, &trace);
    describe("line_eval ext", &air);
    assert!(bad.is_empty(), "violations at (row, lane): {:?}", &bad[..bad.len().min(8)]);
}

#[test]
fn one_altered_result_is_caught_in_its_own_row() {
    let air = transitions_region();
    let mut trace = air.trace();
    let width = air.trace_width();
    let r = air.program().ops.len() / 2;
    trace[r * width + air.c_col()] = trace[r * width + air.c_col()] + Fp::ONE;
    let bad = violations(&air, &trace);
    assert!(!bad.is_empty(), "an altered result went unnoticed");
    assert!(
        bad.iter().all(|(row, _)| *row == r),
        "a row other than the altered one failed: {:?}",
        &bad[..bad.len().min(8)]
    );
}

/// The compose gadget over the real outer, recorded the way the prover
/// evaluates it, over the base field, on its own witness row. Every one of
/// its constraint values is zero, so every output pins to zero, and the
/// three column region over the program is satisfied: this is the wrap's
/// composition region.
#[test]
#[ignore = "release tier: proves the cap-two outer under Poseidon"]
fn the_compose_gadget_over_the_outer_is_a_satisfied_program() {
    use crate::crypto::stark::air::{periodic_root_poseidon, stark_prove_poseidon_pre_rounds};
    use crate::recursion_assembly::compose_step::compose_gen_region;
    use crate::recursion_assembly::inner::{hasher, pack_air, EXTRA, GRIND};

    let h: Poseidon = hasher();
    let mut asm = typed_outer(2);
    let publics = asm.publics.clone();
    let root = periodic_root_poseidon(&asm.gen, EXTRA, &h);
    let mut witness = core::mem::take(&mut asm.witness);
    let Some((rounds, air)) =
        stark_prove_poseidon_pre_rounds(asm.gen, &mut witness, 8, GRIND, EXTRA, &h, &publics, &[])
    else {
        panic!("the typed outer carries no permutation columns above its regions");
    };
    drop(witness);
    let inner = pack_air(&h, air, rounds, publics, root, EXTRA, GRIND);
    let (gadget, row) = compose_gen_region(inner);
    let width = Air::trace_width(&gadget);
    assert_eq!(row.len(), width * (1usize << Air::log_trace_len(&gadget)));

    Rec::<Fp>::start();
    let cells: Vec<Rec<Fp>> = (0..width).map(|i| Rec::input(i, row[i])).collect();
    let outs: Vec<Rec<Fp>> = gadget.transition_gen::<Rec<Fp>>(&cells, &[]);
    let tape = Rec::<Fp>::take();
    let nonzero = outs.iter().filter(|r| tape.vals[r.id() as usize] != Fp::ZERO).count();
    assert_eq!(nonzero, 0, "{nonzero} of {} compose constraints are not zero on the witness", outs.len());
    let outputs: Vec<u32> = outs.iter().map(|r| r.id()).collect();
    let (consts, inputs, adds, subs, muls, invs) = tape.counts();
    println!(
        "compose over the outer as a program: {} ops = {consts} constants + {inputs} inputs + {adds} adds + {subs} subs + {muls} muls + {invs} invs; {} outputs, all zero",
        tape.len(),
        outputs.len()
    );
    let region = LineEval::new_base(tape.program(&outputs));
    describe("line_eval base, compose over the outer", &region);
    let trace = region.trace();
    let bad = violations(&region, &trace);
    assert!(bad.is_empty(), "violations at (row, lane): {:?}", &bad[..bad.len().min(8)]);
}
