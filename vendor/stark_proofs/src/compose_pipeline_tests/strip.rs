// NONOS Operating System (AGPL-3.0-or-later)
//! The strip region and the flat compose it replaces, proven to agree.


use crate::compose_pipeline::{begin, snapshot, Cell};
use crate::crypto::stark::air::GenericTransition;
use crate::crypto::stark::field::{Ext2, Fp};

use super::tape::*;

/// The region gate: the ComposeStrip built from the emitted plan satisfies
/// its own transition, periodic schedule, and boundary over the real tape's
/// witness, the final accumulators plus the statement parts reproduce every
/// output, and one bent schedule coefficient is named by anchor and lane.
#[test]
#[ignore]
fn the_strip_region_satisfies() {
    use crate::compose_pipeline::{check_region, strip_layout, strip_plan};
    let js = crate::shield_deployed_wired();
    let w = 2 * crate::crypto::stark::air::Air::trace_width(&js);
    let p = crate::crypto::stark::air::Air::periodic_columns(&js).len();
    let cells = begin(2 * (w + p));
    let frame: Vec<Ext2<Cell>> =
        (0..w).map(|i| Ext2::new(cells[2 * i], cells[2 * i + 1])).collect();
    let per: Vec<Ext2<Cell>> = (0..p)
        .map(|i| Ext2::new(cells[2 * (w + i)], cells[2 * (w + i) + 1]))
        .collect();
    let outs = js.transition_gen::<Ext2<Cell>>(&frame, &per);
    let tape = snapshot();
    let out_ids: Vec<u32> = outs.iter().flat_map(|o| [o.c0.0, o.c1.0]).collect();

    let lay = strip_layout(&tape, &out_ids, 4);
    let (plan, stmt) = strip_plan(&tape, &lay);
    std::println!(
        "region: {} rows (padded {}), width {}, {} periodic columns",
        plan.rows.len(),
        1usize << {
            let mut lg = 1u32;
            while (1usize << lg) < plan.rows.len() { lg += 1; }
            lg
        },
        plan.k + plan.echo_width + plan.n_out,
        2 * (plan.candidates() + 1) * plan.k + plan.n_out * plan.k
    );
    for seed in [991177u64, 7] {
        let inputs = random_fps(2 * (w + p), seed);
        assert!(
            check_region(&tape, &plan, &stmt, &inputs, &out_ids).is_none(),
            "an honest witness violated the region"
        );
    }

    // Provoked: bend one schedule coefficient; the region must name it.
    let inputs = random_fps(2 * (w + p), 991177);
    let mut bent = plan.clone();
    'bend: for row in bent.rows.iter_mut() {
        for (l, (a, _)) in row.ops.iter_mut().enumerate() {
            if row.lanes[l] != crate::crypto::stark::air::EMPTY {
                for c in a.coeffs.iter_mut() {
                    if *c != Fp::ZERO {
                        *c = *c + Fp::ONE;
                        break 'bend;
                    }
                }
            }
        }
    }
    let miss = check_region(&tape, &bent, &stmt, &inputs, &out_ids);
    assert!(miss.is_some(), "a bent schedule satisfied the region");
    std::println!("bent schedule named at {:?}", miss.unwrap());
}

/// The strip-mode flat region: recompute out, pins in. Built over the real
/// inner with honest values, every constraint at the single anchor must
/// vanish, acc cells carrying out minus statement by construction.
#[test]
#[ignore]
fn the_strip_mode_flat_satisfies() {
    use crate::compose_pipeline::{strip_layout, strip_plan};
    use crate::crypto::stark::air::{compose_ext, Air, ComposeCheckGen};
    let js = crate::shield_deployed_wired();
    let wdt = crate::crypto::stark::air::Air::trace_width(&js);
    let w = 2 * wdt;
    let p = crate::crypto::stark::air::Air::periodic_columns(&js).len();
    let cells = begin(2 * (w + p));
    let frame_c: Vec<Ext2<Cell>> =
        (0..w).map(|i| Ext2::new(cells[2 * i], cells[2 * i + 1])).collect();
    let per_c: Vec<Ext2<Cell>> = (0..p)
        .map(|i| Ext2::new(cells[2 * (w + i)], cells[2 * (w + i) + 1]))
        .collect();
    let outs = js.transition_gen::<Ext2<Cell>>(&frame_c, &per_c);
    let tape = snapshot();
    let out_ids: Vec<u32> = outs.iter().flat_map(|o| [o.c0.0, o.c1.0]).collect();
    let lay = strip_layout(&tape, &out_ids, 4);
    let (_, stmt) = strip_plan(&tape, &lay);

    use crate::crypto::stark::field::Fp2;
    let inputs = random_fps(2 * (w + p), 40499);
    let frame: Vec<Fp2> =
        (0..w).map(|i| Fp2 { c0: inputs[2 * i], c1: inputs[2 * i + 1] }).collect();
    let periodic: Vec<Fp2> = (0..p)
        .map(|i| Fp2 { c0: inputs[2 * (w + i)], c1: inputs[2 * (w + i) + 1] })
        .collect();
    let nt = js.num_transition();
    let b = js.boundary().len();
    let coeffs: Vec<Fp2> = random_fps(2 * (nt + b), 7)
        .chunks(2)
        .map(|c| Fp2 { c0: c[0], c1: c[1] })
        .collect();
    let zr = random_fps(2, 991177);
    let z = Fp2 { c0: zr[0], c1: zr[1] };
    let g = crate::crypto::stark::fri::root_of_unity(js.log_trace_len());
    let comp_z = compose_ext(&js, g, z, &frame, &periodic, &coeffs);

    let region = ComposeCheckGen::new_witness(
        crate::shield_deployed_wired(),
        frame,
        periodic,
        coeffs,
        z,
        comp_z,
        g,
    )
    .into_strip(stmt);
    let tr = region.trace();
    let wid = region.trace_width();
    let window: Vec<Fp> = tr[..2 * wid].to_vec();
    let res = region.transition(&window, &[]);
    for (i, v) in res.iter().enumerate() {
        assert!(*v == Fp::ZERO, "strip-mode flat constraint {i} does not vanish");
    }
    std::println!(
        "flat strip mode: width {}, {} constraints vanish, degree {}",
        wid,
        res.len(),
        region.constraint_degree()
    );
}

/// The model-to-code bridge for the S-box split. Zkolang.SboxSplit proves over the
/// integers that x4 * x2 * y equals y^7 when x2 = y*y and x4 = x2*x2, and that the honest
/// squares always satisfy the two square constraints. This asserts the real Rust round
/// implements exactly that identity: round_split_generic with the honest squares
/// reproduces the closed round_generic on random states, and its returned square
/// constraints vanish. The Lean identity and the deployed field op now meet in CI, not in
/// anyone's head.
#[test]
fn the_sbox_split_matches_the_lean_model() {
    use crate::crypto::stark::air::{Poseidon, RATE, WIDTH};
    use crate::crypto::stark::field::Fp;

    let h = Poseidon::new(13, [Fp::from_u64(0); RATE]);
    for seed in [1u64, 7, 40499, 991177, 0xdeadbeef] {
        let mut s = seed;
        let mut state = [Fp::ZERO; WIDTH];
        let mut rc = [Fp::ZERO; WIDTH];
        for j in 0..WIDTH {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            state[j] = Fp::from_u64(s >> 11);
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            rc[j] = Fp::from_u64(s >> 11);
        }
        // The honest witness the Lean completeness lemma names: x2 = y*y, x4 = x2*x2.
        let mut x2 = [Fp::ZERO; WIDTH];
        let mut x4 = [Fp::ZERO; WIDTH];
        for j in 0..WIDTH {
            x2[j] = state[j] * state[j];
            x4[j] = x2[j] * x2[j];
        }
        let closed = h.round_generic::<Fp>(&state, &rc);
        let (split, c2, c4) = h.round_split_generic::<Fp>(&state, &x2, &x4, &rc);
        // Soundness: the split S-box output equals the closed y^7 round, lane for lane.
        assert_eq!(closed, split, "split round diverges from closed round at seed {seed}");
        // Completeness: the honest squares make both constraint vectors vanish.
        for j in 0..WIDTH {
            assert_eq!(c2[j], Fp::ZERO, "x2 constraint nonzero at lane {j}, seed {seed}");
            assert_eq!(c4[j], Fp::ZERO, "x4 constraint nonzero at lane {j}, seed {seed}");
        }
    }
}
