// NONOS Operating System (AGPL-3.0-or-later)
//! Laying one or more inners' parts end to end and binding them into one engine.

use super::build::build_groups;
use super::inner::LOG_ROUNDS;
use super::layout::{offsets, Layout};
use super::gen::AggregateGen;
use super::parts::{ComposeForm, Parts};
use super::{groups, strip};
use crate::crypto::stark::air::{
    AirExt, GenRegion, GenericTransition, OuterRegion, WiredMultiExt, WiredMultiGen,
};
use crate::crypto::stark::field::Fp;
use alloc::boxed::Box;
use alloc::vec::Vec;

/*
 * The constraint body each region runs, in the order the regions are pushed.
 * Three switches decide the list. The accumulator strip exists only on the
 * aggregating path, so an outer built by `combine` carries a body that the
 * single region fixture never builds; the periodic-z region is present exactly
 * when the sidecar is off, the sidecar replacing it with a per query
 * authentication instead; and a two round inner adds one more authentication
 * per query, for the half of the row its second root commits. Deriving the
 * names from the same switches the layout uses keeps the emitted map from
 * drifting away from the region list, which a written out table would do at
 * the first reorder.
 */
pub(super) fn body_names(
    with_strip: bool,
    program: bool,
    with_sidecar: bool,
    with_rounds: bool,
) -> Vec<(&'static str, &'static str)> {
    let mut v: Vec<(&'static str, &'static str)> = alloc::vec![("transcript", "stark_transcript")];
    if program {
        v.push(("eval", "line_eval"));
    } else {
        v.push(("compose", "compose"));
        if with_strip {
            v.push(("strip", "accumulator_strip"));
        }
    }
    v.push(("powers", "coeff_powers"));
    v.push(("powers", "deep_powers"));
    v.push(("transcript", "fri_transcript"));
    if !with_sidecar {
        v.push(("periodic_z", "periodic_at_z"));
    }
    /*
     * Four of these run one body between them: the membership body is a Merkle
     * chain and knows nothing about what it authenticates. What differs is the
     * anchor. The FRI, trace and permutation chains terminate at roots the
     * proof carries, bound to the transcript's absorb cells; the periodic chain
     * terminates at a root baked in at deployment and pinned as a constant.
     * Taking that one from the proof would let the prover choose the schedule
     * it is checked against, so the role is emitted beside the body.
     */
    v.extend_from_slice(&[
        ("deep", "deep_quotient"),
        ("fold", "fri_fold"),
        ("membership", "fri_auth"),
        ("membership", "trace_auth"),
    ]);
    if with_rounds {
        v.push(("membership", "perm_auth"));
    }
    if with_sidecar {
        v.push(("membership", "periodic_auth"));
    }
    v.extend_from_slice(&[
        ("horner", "final_value"),
        ("draw", "consistency_draw"),
        ("draw", "fold_draw"),
    ]);
    v
}
/// An outer over one or more inners: the same engine, one layout per inner.
pub struct Aggregate {
    pub wired: WiredMultiExt,
    pub witness: Vec<Fp>,
    pub lays: Vec<Layout>,
    pub publics: Vec<Fp>,
    pub n_groups: usize,
    pub region_offsets: Vec<usize>,
    /// Which constraint body each kind runs, and the role it plays, in kind
    /// order. See `Assembly`.
    pub kind_bodies: Vec<(&'static str, &'static str)>,
}

/// How the copy constraint is argued. Same permutation, same classes, either
/// way; what differs is what the verifier carries.
///
/// A parameter rather than a setting, because an artifact has to say what it
/// is. A switch that could be set out of band is how an inner got emitted at
/// eighty bits under a name claiming a hundred and forty four.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Wiring {
    /// Classes bin-packed into groups of at most eight columns, one grand
    /// product each. A column wired in many classes carries a sigma column in
    /// every group that holds one of them.
    Packed,
    /// One permutation over every wired column, its product chained through
    /// accumulators so each lane still multiplies at most eight factors. One
    /// sigma column per wired column, whatever the classes look like.
    Chained,
}

impl Wiring {
    pub fn name(self) -> &'static str {
        match self {
            Wiring::Packed => "packed",
            Wiring::Chained => "chained",
        }
    }
}

/// Lay the parts end to end and bind them into one engine. Every inner keeps its
/// own layout over the shared trace, so its regions are bound only to its own
/// openings; the kinds repeat, so the constraint set does not grow with the
/// number of inners and only the row count does.
/// Laying and binding, keeping the regions by name. Every existing caller goes
/// through `gen::combine_wired`, which is this with the names dropped, and
/// sees exactly what it saw; a wrap over this outer takes the named form
/// because it has to recompute each region over the tower, and a box cannot
/// be asked for that.
pub(super) fn combine_wired_gen<A: AirExt + GenericTransition + 'static>(
    parts: Vec<Parts<A>>,
    wiring: Wiring,
    anchors: super::anchors::Anchors,
) -> AggregateGen<A> {
    assert!(!parts.is_empty(), "an outer needs at least one inner");
    let with_sidecar = parts[0].with_sidecar;
    let with_rounds = parts[0].with_rounds;
    let n_q = parts[0].n_q;
    let program = parts[0].form == ComposeForm::Program;
    for p in &parts {
        assert!(p.form == parts[0].form, "aggregated inners must share their compose form");
        assert!(
            p.with_sidecar == with_sidecar && p.with_rounds == with_rounds && p.n_q == n_q,
            "aggregated inners must share their shape"
        );
    }

    let mut gens: Vec<OuterRegion<A>> = Vec::new();
    let mut traces: Vec<Vec<Fp>> = Vec::new();
    let mut starts: Vec<usize> = Vec::with_capacity(parts.len());
    let mut publics: Vec<Fp> = Vec::new();
    let mut parts = parts;
    for p in parts.iter_mut() {
        starts.push(gens.len());
        gens.append(&mut p.gens);
        traces.append(&mut p.traces);
        publics.extend_from_slice(&p.publics);
    }
    // The boxes the engine stacks are views of the named regions, not copies,
    // so what the wrap recomputes and what the prover proves is one value.
    let regions: Vec<Box<dyn AirExt>> = gens.iter().map(|g| g.boxed()).collect();
    let (off, span) = offsets(&regions);

    // Shared regions first, then one block per query. Both counts are switch
    // driven and both are read again below for the kind list, so they are
    // named once here.
    // Transcript, the composition in one or two regions, the two powers
    // regions, the FRI transcript, and the periodic recompute when there is
    // no sidecar.
    let base = (if with_sidecar { 6 } else { 7 }) - usize::from(program);
    let stride = 7 + usize::from(with_sidecar) + usize::from(with_rounds);
    let mut lays: Vec<Layout> = Vec::with_capacity(parts.len());
    for (p, &s) in parts.iter().zip(starts.iter()) {
        let o = &off[s..];
        let (c_off, strip_off, cp_off, dp_off, ft_off) = if program {
            (o[1], 0, o[2], o[3], o[4])
        } else {
            (o[1], o[2], o[3], o[4], o[5])
        };
        // The strip's cycles in absolute coordinates: echoes to producers,
        // final accumulators to the flat acc cells.
        let mut strip_cycles: Vec<((usize, usize), (usize, usize))> = Vec::new();
        for ((r, col), home) in &p.cycles {
            let a = (strip_off + r, *col);
            let b = match home {
                strip::Home::Flat(u) => (c_off, *u),
                strip::Home::Strip(pr, pc) => (strip_off + pr, *pc),
            };
            strip_cycles.push((a, b));
        }
        for (j, sc) in p.acc_cols.iter().enumerate() {
            strip_cycles.push((
                (strip_off + p.final_row, *sc),
                (c_off, p.flat_acc[j / 2] + (j % 2)),
            ));
        }
        for (a, b) in &p.eval_cycles {
            strip_cycles.push(((c_off + a.0, a.1), (c_off + b.0, b.1)));
        }
        let pz_off = if with_sidecar { 0 } else { o[base - 1] };
        let d_off: Vec<usize> = (0..n_q).map(|k| o[base + k * stride]).collect();
        let f_off: Vec<usize> = (0..n_q).map(|k| o[base + k * stride + 1]).collect();
        let m_off: Vec<usize> = (0..n_q).map(|k| o[base + k * stride + 2]).collect();
        let ta_off: Vec<usize> = (0..n_q).map(|k| o[base + k * stride + 3]).collect();
        let ra_off: Vec<usize> = if with_rounds {
            (0..n_q).map(|k| o[base + k * stride + 4]).collect()
        } else {
            Vec::new()
        };
        let pa_off: Vec<usize> = if with_sidecar {
            let at = 4 + usize::from(with_rounds);
            (0..n_q).map(|k| o[base + k * stride + at]).collect()
        } else {
            Vec::new()
        };
        let h_off: Vec<usize> = (0..n_q)
            .map(|k| o[base + k * stride + stride - 3])
            .collect();
        let i_off: Vec<usize> = (0..n_q)
            .map(|k| o[base + k * stride + stride - 2])
            .collect();
        let fp_off: Vec<usize> = (0..n_q)
            .map(|k| o[base + k * stride + stride - 1])
            .collect();

        lays.push(Layout {
            span,
            l: 1usize << LOG_ROUNDS,
            n_q,
            i0: p.i0,
            c_off,
            cp_off,
            dp_off,
            ft_off,
            pz_off,
            d_off,
            f_off,
            m_off,
            h_off,
            i_off,
            fp_off,
            draw_value_row: crate::crypto::stark::air::DRAW_BITS,
            horner_value_row: p.cells.n_final,
            n_final: p.cells.n_final,
            cells: p.cells.clone(),
            ta_off,
            tchunk_cells: p.tchunk_cells.clone(),
            ta_depth: p.ta_depth,
            rounds: with_rounds,
            ra_off,
            rchunk_cells: p.rchunk_cells.clone(),
            ra_depth: p.ra_depth,
            beta_op: p.beta_op.unwrap_or(0),
            coeff_op: p.coeff_op,
            strip_cycles,
            strip_off,
            strip_k: p.strip_k,
            strip_echo_width: p.strip_echo_width,
            strip_n_out: p.strip_n_out,
            strip_rows: p.strip_rows,
            compose_acc_base_col: p.flat_acc.first().copied().unwrap_or(0),
            z_op: p.z_op,
            deep_coeff_op: p.deep_coeff_op,
            pub_len: p.pub_len,
            c_pub_col: p.c_pub_col,
            n_pub: p.n_pub,
            n_terms: p.n_terms,
            width_inner: p.width_inner,
            /*
             * The sidecar appends one term per periodic column behind the frame
             * and composition terms; the window is what remains, and it divides
             * exactly or the term list is not what this layout thinks it is.
             */
            window_inner: {
                let frame_terms = p.n_terms - 1 - p.pchunk_len;
                assert!(
                    frame_terms % p.width_inner == 0,
                    "deep terms do not tile the frame: {frame_terms} over width {}",
                    p.width_inner
                );
                frame_terms / p.width_inner
            },
            ocells: p.ocells.clone(),
            depth: p.depth,
            n_open: p.n_open,
            n_folds: p.n_folds,
            log_n: p.log_n,
            pbits: p.pbits,
            fbits: p.fbits,
            t_inner: p.t_inner,
            n_pz: p.n_pz,
            sidecar: with_sidecar,
            pa_off,
            pchunk_cells: p.pchunk_cells.clone(),
            pa_depth: p.pa_depth,
            n_pz_absorb_chunks: p.n_pz.div_ceil(crate::crypto::stark::air::RATE),
            frame_len: p.frame_len,
            n_coeff: p.n_coeff,
            c_periodic_col: p.c_periodic_col,
            c_z_col: p.c_z_col,
            c_coeff_col: p.c_coeff_col,
            c_comp_z_col: p.c_comp_z_col,
            n_chal: p.n_chal,
            c_chal_col: p.c_chal_col,
            c_rows: p.c_rows.clone(),
        });
    }

    std::eprintln!("[asm] offsets/layout");
    /*
     * Every inner's binds are built against its own layout and collapse together
     * over the one trace, so an inner's regions stay bound to that inner's
     * openings and nothing crosses between them.
     */
    let mut binds: Vec<groups::Bind> = Vec::new();
    for lay in &lays {
        binds.extend(build_groups(lay));
    }
    // The chain anchors: one pin per distinct constant and a class over every
    // cell sharing it, in place of one boundary per cell. `anchors.rs`.
    let (mut pins, anchor_binds) =
        super::anchors::anchor_pins(&parts, &lays, n_q, with_rounds, anchors);
    binds.extend(anchor_binds);
    let n_public_pins = super::anchors::public_pins(&parts, &lays, &mut pins);
    let width = regions.iter().map(|r| r.trace_width()).max().unwrap_or(1);
    /*
     * Both forms start from the same classes: the packer cuts them into
     * groups, the single permutation lays them into one slot space. Changing
     * the classes changes the statement, so they are gated by digest and
     * neither form derives them its own way.
     */
    let gps = match wiring {
        Wiring::Packed => groups::collapse(&binds, span, width),
        Wiring::Chained => {
            let classes = groups::wiring_classes(&binds, span, width);
            alloc::vec![groups::single_group(&classes, span, width)]
        }
    };
    std::eprintln!("[asm] groups fused ({})", wiring.name());
    let n_groups = gps.len();
    let shared = base;
    let per_q = stride;
    /*
     * The kinds repeat across inners: an inner's region has the same shape and
     * the same rules whichever inner it belongs to, so the constraint set is
     * fixed and only the rows grow with the count.
     */
    let one: Vec<usize> = (0..shared)
        .chain((0..n_q).flat_map(|_| shared..shared + per_q))
        .collect();
    let kinds: Vec<usize> = (0..lays.len()).flat_map(|_| one.iter().copied()).collect();
    let mut wired = match wiring {
        Wiring::Packed => WiredMultiExt::new_kinds_bounded(regions, &kinds, gps, pins),
        Wiring::Chained => WiredMultiExt::new_kinds_chained(
            regions,
            &kinds,
            gps.into_iter()
                .next()
                .expect("the chained form builds one permutation"),
            pins,
        ),
    };
    wired.mark_public_pins(n_public_pins);
    std::eprintln!("[asm] engine built");
    let witness = wired.trace(&traces);
    std::eprintln!("[asm] witness placed");
    /*
     * The aggregating path always builds the accumulator strip, so its kind
     * list carries a body the fixture assembly never runs and every kind after
     * compose sits one place later than it does there. A port that assumes the
     * fixture's kind order lands on the wrong body from compose onward, which
     * is the reason this is emitted rather than described.
     */
    let bodies = body_names(true, program, with_sidecar, with_rounds);
    // Not a debug assertion: this crate is built and tested under --release
    // everywhere, so a debug assertion here checks nothing, and a body list
    // one entry off is a verifier dispatching the wrong rule from that kind on.
    assert_eq!(
        bodies.len(),
        shared + per_q,
        "the body list and the kind list must describe the same regions"
    );
    AggregateGen {
        gen: WiredMultiGen::from_parts(wired, gens),
        witness,
        lays,
        publics,
        n_groups,
        region_offsets: off,
        kind_bodies: bodies,
    }
}
