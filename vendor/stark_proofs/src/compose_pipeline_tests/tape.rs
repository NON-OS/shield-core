// NONOS Operating System (AGPL-3.0-or-later)
//! The recording is faithful or the strip is fiction: run the real inner's
//! transition over the tape, replay the tape over random values, and the
//! replayed outputs must equal the direct evaluation's, output for output.

use crate::compose_pipeline::{begin, eval, mul_count, snapshot, Cell};
use crate::crypto::stark::air::GenericTransition;
use crate::crypto::stark::field::{Ext2, Fp};

pub(super) fn random_fps(n: usize, seed: u64) -> Vec<Fp> {
    // A fixed-seed LCG: deterministic test values, no rng dependency.
    let mut s = seed;
    (0..n)
        .map(|_| {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            Fp::from_u64(s >> 11)
        })
        .collect()
}

pub(super) fn tape_matches_direct<A: GenericTransition>(air: &A, w: usize, p: usize, seed: u64) {
    // Record: 2 base lanes per Ext2 value, frame then periodic.
    let cells = begin(2 * (w + p));
    let frame: Vec<Ext2<Cell>> =
        (0..w).map(|i| Ext2::new(cells[2 * i], cells[2 * i + 1])).collect();
    let per: Vec<Ext2<Cell>> = (0..p)
        .map(|i| Ext2::new(cells[2 * (w + i)], cells[2 * (w + i) + 1]))
        .collect();
    let out_cells = air.transition_gen::<Ext2<Cell>>(&frame, &per);
    let tape = snapshot();

    // Replay over random values and evaluate directly over the same values.
    let inputs = random_fps(2 * (w + p), seed);
    let vals = eval(&tape, &inputs);
    let frame_v: Vec<Ext2<Fp>> =
        (0..w).map(|i| Ext2::new(inputs[2 * i], inputs[2 * i + 1])).collect();
    let per_v: Vec<Ext2<Fp>> = (0..p)
        .map(|i| Ext2::new(inputs[2 * (w + i)], inputs[2 * (w + i) + 1]))
        .collect();
    let direct = air.transition_gen::<Ext2<Fp>>(&frame_v, &per_v);

    assert_eq!(out_cells.len(), direct.len());
    for (i, (oc, dv)) in out_cells.iter().zip(&direct).enumerate() {
        let replayed = Ext2::new(vals[oc.c0.0 as usize], vals[oc.c1.0 as usize]);
        assert!(replayed == *dv, "output {i} diverges between tape and direct");
    }
    std::println!(
        "tape: {} nodes, {} muls, {} outputs",
        tape.len(),
        mul_count(&tape),
        direct.len()
    );
}

/// The strip plan for the real tape: every mul scheduled at its level, every
/// producer's liveness reaching its consumers, the window-2 audit green, and
/// the width pressure printed so the budget is a number, not a hope.
#[test]
#[ignore]
fn the_real_tape_schedules() {
    use crate::compose_pipeline::{audit, plan};
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

    let pl = plan(&tape, &out_ids);
    assert!(audit(&tape, &pl), "a scheduled operand escaped its window");
    std::println!(
        "strip: {} muls over {} rows, peak carry {}, inputs {}, width pressure {}",
        pl.slots.len(),
        pl.rows,
        pl.peak_carry,
        pl.n_inputs,
        pl.n_inputs + 2 * pl.peak_carry
    );

    let wm = crate::compose_pipeline::witnessed_muls(&tape);
    std::println!("witnessed (var x var) muls: {} of {}", wm.len(), 3525);

    for k in [2usize, 4, 8, 16, 32] {
        let pk = crate::compose_pipeline::pack(&tape, &out_ids, k);
        std::println!(
            "pack k={k}: rows={} echo={} width={} (carry={} inputs={} fed={})",
            pk.rows,
            pk.peak_echo,
            pk.width,
            pk.peak_carry,
            pk.peak_inputs,
            pk.n_output_fed
        );
    }
}

/// The deployed join-split: the inner the settlement recursion carries.
/// Release-gated like the other real-inner walks; the debug build trips a
/// pre-existing debug assert inside the deployed assembly's construction.
#[test]
#[ignore]
fn the_real_inner_records_faithfully() {
    let js = crate::shield_deployed_wired();
    let w = 2 * crate::crypto::stark::air::Air::trace_width(&js);
    let p = crate::crypto::stark::air::Air::periodic_columns(&js).len();
    for seed in [7u64, 40499, 991177] {
        tape_matches_direct(&js, w, p, seed);
    }
}

/// The layout gate: evaluate every lane's linear forms and the accumulator
/// schedule against the replayed tape. Product by product, output by output,
/// the layout must reproduce the recording it was compiled from.
#[test]
#[ignore]
fn the_strip_layout_evaluates() {
    use crate::compose_pipeline::{strip_layout, Source};
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

    let k = 32usize;
    let lay = strip_layout(&tape, &out_ids, k);
    let inputs = random_fps(2 * (w + p), 40499);
    let vals = eval(&tape, &inputs);

    let resolve = |row: usize, s: &Source, lay: &crate::compose_pipeline::StripLayout| -> Fp {
        match s {
            Source::Slot { rel, lane } => {
                let r = if *rel == 1 { row } else { row - 1 };
                vals[lay.rows[r].lanes[*lane as usize].node as usize]
            }
            Source::Echo { idx } => vals[lay.rows[row].echoes[*idx as usize] as usize],
        }
    };

    let mut checked = 0usize;
    let mut max_echo = 0usize;
    for (r, row) in lay.rows.iter().enumerate() {
        max_echo = max_echo.max(row.echoes.len());
        for lane in &row.lanes {
            let ev = |f: &crate::compose_pipeline::LinForm| -> Fp {
                let mut acc = f.constant;
                for (c, s) in &f.terms {
                    acc = acc + *c * resolve(r, s, &lay);
                }
                acc
            };
            let a = ev(&lane.a);
            let b = ev(&lane.b);
            assert!(a * b == vals[lane.node as usize], "lane {} row {r} lies", lane.node);
            checked += 1;
        }
    }

    for (j, out) in out_ids.iter().enumerate() {
        let mut acc = lay.out_consts[j];
        for (r, c, s) in &lay.out_terms[j] {
            acc = acc + *c * resolve(*r, s, &lay);
        }
        assert!(acc == vals[*out as usize], "output {j} diverges");
    }
    std::println!(
        "layout: {} lanes checked over {} rows, max echoes {}, outputs {} exact",
        checked,
        lay.rows.len(),
        max_echo,
        out_ids.len()
    );
}

/// The operand-width census: how many sources each linear form reads decides
/// the term-cell budget T and how many wide forms split into partial sums.
#[test]
#[ignore]
fn the_operand_widths_measure() {
    use crate::compose_pipeline::strip_layout;
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
    let lay = strip_layout(&tape, &out_ids, 32);

    let mut hist: std::collections::BTreeMap<usize, usize> = Default::default();
    let mut consts = 0usize;
    for row in &lay.rows {
        for lane in &row.lanes {
            for f in [&lane.a, &lane.b] {
                *hist.entry(f.terms.len()).or_insert(0) += 1;
                if f.constant != Fp::ZERO {
                    consts += 1;
                }
            }
        }
    }
    let max_out = lay.out_terms.iter().map(|t| t.len()).max().unwrap_or(0);

    // The wide forms: where do their sources live relative to the lane's row?
    let mut same_window = 0usize;
    let mut spread = 0usize;
    let mut echo_heavy = 0usize;
    for row in &lay.rows {
        for lane in &row.lanes {
            for f in [&lane.a, &lane.b] {
                if f.terms.len() < 8 {
                    continue;
                }
                let echoes = f
                    .terms
                    .iter()
                    .filter(|(_, s)| matches!(s, crate::compose_pipeline::Source::Echo { .. }))
                    .count();
                if echoes == 0 {
                    same_window += 1;
                } else if echoes * 2 < f.terms.len() {
                    spread += 1;
                } else {
                    echo_heavy += 1;
                }
            }
        }
    }
    std::println!(
        "wide forms: {} window-only, {} mixed, {} echo-heavy",
        same_window, spread, echo_heavy
    );

    // One wide form dissected: are its echo sources inputs or products?
    'outer: for row in &lay.rows {
        for lane in &row.lanes {
            for f in [&lane.a, &lane.b] {
                if f.terms.len() != 33 {
                    continue;
                }
                let mut inputs = 0usize;
                let mut products = 0usize;
                for (_, src) in &f.terms {
                    if let crate::compose_pipeline::Source::Echo { idx } = src {
                        let id = row.echoes[*idx as usize];
                        match &tape[id as usize] {
                            crate::compose_pipeline::Node::Input(_) => inputs += 1,
                            _ => products += 1,
                        }
                    }
                }
                std::println!(
                    "a 33-form: {} input echoes, {} product echoes, {} window terms",
                    inputs, products, 33 - inputs - products
                );
                break 'outer;
            }
        }
    }
    std::println!("operand terms histogram: {hist:?}");
    std::println!("operands with nonzero constant: {consts}");
    std::println!("widest output form: {max_out} terms");
}
