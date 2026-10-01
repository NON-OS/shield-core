// NONOS Operating System (AGPL-3.0-or-later)
//! Assembling the wired recursive verifier: prove the inner join-split, build the
//! shared regions and one DEEP, fold, auth and index-point block per inner query,
//! lay them out, bind them, and place the witness. Each block is bound only to its
//! own query's openings and index. A tamper alters one query's witness only.

use super::aggregate::body_names;
pub use super::aggregate::{Aggregate, Wiring};
use super::gen::combine_wired;
use super::inner::{Inner, LOG_ROUNDS};
use super::layout::{offsets, Layout};
use super::parts::{parts_over, TranscriptCells};
use super::tamper::Tamper;
use super::{
    auth, compose, deep, finals, fri, groups, inner, periodic, points, powers, transcript,
};
use crate::crypto::stark::air::{Air, AirExt, GenericTransition, GpGroup, Poseidon, WiredMultiExt};
use crate::crypto::stark::field::{Fp, Fp2};
use alloc::boxed::Box;
use alloc::vec::Vec;

pub struct Assembly {
    pub wired: WiredMultiExt,
    pub witness: Vec<Fp>,
    pub lay: Layout,
    pub publics: Vec<Fp>,
    pub n_groups: usize,
    /// Each region's first row in the stacked trace, in region order.
    pub region_offsets: Vec<usize>,
    /*
     * Which constraint body each kind runs, in kind order: a property of how
     * the regions were pushed, not recoverable from the trace or the layout,
     * carried so the chain side is driven by the emitted shape rather than a
     * transcribed table that rots when the region list changes.
     */
    pub kind_bodies: Vec<(&'static str, &'static str)>,
}

/// The join-split recursion attesting every inner query, with `tamper` applied to
/// query 0 (the historic single-query reject cases).
pub fn assemble(tamper: Tamper) -> Assembly {
    assemble_q(tamper, 0)
}

/// The same with `tamper` applied to inner query `tamper_q`: a tamper on any
/// query must reject through that query's own block, which is the proof inner
/// coverage is closed rather than query-0-only.
pub fn assemble_q(tamper: Tamper, tamper_q: usize) -> Assembly {
    assemble_capped(tamper, tamper_q, usize::MAX)
}

/// The same attesting only the first `cap` inner queries: the identical
/// per-query machinery over a far smaller trace, so a real FRI prove and
/// verify can exercise the degree bounds and the wiring end to end.
pub fn assemble_capped(tamper: Tamper, tamper_q: usize, cap: usize) -> Assembly {
    let h = inner::hasher();
    let inner = inner::join_split(&h);
    let n_q = inner.proof.queries.len().min(cap);

    // Shared regions: transcript, compose, both powers, FRI transcript, periodic.
    let (cregion, ctrace) = compose::compose_region(&inner);
    let ts = transcript::stark_transcript(&h, &inner);
    let ft = fri::fri_transcript(&h, &inner, ts.seed);
    let mut deep_coeffs: Vec<Fp2> = Vec::new();
    let with_sidecar = false;
    let pz = Some(periodic::periodic_region(&inner, tamper));

    // One dependent-region block per query, in [deep, fold, auth, tauth, ip, fp]
    // order. The per-query metadata is uniform, taken from query 0.
    let mut q_boxes: Vec<Box<dyn AirExt>> = Vec::new();
    let mut q_traces: Vec<Vec<Fp>> = Vec::new();
    let mut n_terms = 0usize;
    let mut ocells: Vec<Vec<(usize, usize)>> = Vec::with_capacity(n_q);
    let mut tchunk_cells: Vec<Vec<(usize, usize)>> = Vec::with_capacity(n_q);
    let (mut depth, mut n_open, mut pbits, mut fbits) = (0usize, 0usize, 0usize, 0usize);
    let mut i0 = 0usize;
    let mut ta_depth = 0usize;
    for k in 0..n_q {
        let tk = if k == tamper_q { tamper } else { Tamper::None };
        std::eprintln!("[asm] q{k} deep");
        let (dreg, dtr, nt) = deep::deep_region_k(&h, &inner, k, tk);
        std::eprintln!("[asm] q{k} fold");
        let fold = fri::fri_fold_k(&inner, &ft, k, tk);
        std::eprintln!("[asm] q{k} auth");
        let au = auth::auth_side_k(&h, &inner, fold.ik, k, tk);
        let ta = auth::trace_auth_k(&h, &inner, &au.cons_dirs, k);
        std::eprintln!("[asm] q{k} points");
        let pts = points::point_regions_k(ft.index_values[k], ft.index_values[k], ft.log_n, k, inner.grind, tk);
        let (hreg, htrace) = finals::horner_k(&inner, &ft, k);
        if k == 0 {
            n_terms = nt;
            deep_coeffs = dreg.coeffs();
            depth = au.depth;
            n_open = au.n_open;
            pbits = pts.pbits;
            fbits = pts.fbits;
            i0 = au
                .cons_dirs
                .iter()
                .enumerate()
                .fold(0, |a, (lv, &b)| a | ((b as usize) << lv));
            ta_depth = ta.depth;
        }
        // Each query's opened-cell columns depend on its own index parity.
        ocells.push(au.ocells.clone());
        tchunk_cells.push(ta.chunk_cells);
        q_boxes.push(Box::new(dreg));
        q_traces.push(dtr);
        q_boxes.push(Box::new(fold.fold));
        q_traces.push(fold.ftrace);
        q_boxes.push(Box::new(au.region));
        q_traces.push(au.trace);
        q_boxes.push(Box::new(ta.region));
        q_traces.push(ta.trace);
        q_boxes.push(Box::new(hreg));
        q_traces.push(htrace);
        q_boxes.push(Box::new(pts.ip));
        q_traces.push(pts.itrace);
        q_boxes.push(Box::new(pts.fp));
        q_traces.push(pts.fptrace);
    }

    std::eprintln!("[asm] queries done");
    let cells = TranscriptCells::of(&ts, &ft, inner.proof.fri.final_layer.len());
    let width_inner = inner.air.trace_width();
    let t_inner = inner.t as usize;
    let (z_op, deep_coeff_op, coeff_op) = (ts.z_op, ts.deep_coeff_op, ts.coeff_op);
    let pub_len = inner.publics.len();
    let honest = tamper == Tamper::None;
    let (cp, cptrace) = powers::powers_region(
        ts.alpha,
        inner.ci.coeffs.len(),
        honest.then_some(&inner.ci.coeffs[..]),
        "composition coefficients",
    );
    let (dp, dptrace) = powers::powers_region(
        ts.deep_alpha,
        n_terms,
        honest.then_some(&deep_coeffs[..]),
        "DEEP coefficients",
    );

    let mut regions: Vec<Box<dyn AirExt>> = alloc::vec![
        Box::new(ts.region) as Box<dyn AirExt>,
        Box::new(cregion),
        Box::new(cp),
        Box::new(dp),
        Box::new(ft.transcript),
    ];
    let mut traces: Vec<Vec<Fp>> = alloc::vec![ts.trace, ctrace, cptrace, dptrace, ft.ttrace];
    if let Some((pzregion, pztrace)) = pz {
        regions.push(Box::new(pzregion));
        traces.push(pztrace);
    }
    regions.extend(q_boxes);
    traces.extend(q_traces);

    let (off, span) = offsets(&regions);
    let (c_off, cp_off, dp_off, ft_off) = (off[1], off[2], off[3], off[4]);
    // Shared count and per-query stride depend on which optional regions run.
    let base = if with_sidecar { 5 } else { 6 };
    let stride = if with_sidecar { 8 } else { 7 };
    let pz_off = if with_sidecar { 0 } else { off[5] };
    let d_off: Vec<usize> = (0..n_q).map(|k| off[base + k * stride]).collect();
    let f_off: Vec<usize> = (0..n_q).map(|k| off[base + k * stride + 1]).collect();
    let m_off: Vec<usize> = (0..n_q).map(|k| off[base + k * stride + 2]).collect();
    let ta_off: Vec<usize> = (0..n_q).map(|k| off[base + k * stride + 3]).collect();
    let pa_off: Vec<usize> = if with_sidecar {
        (0..n_q).map(|k| off[base + k * stride + 4]).collect()
    } else {
        Vec::new()
    };
    let h_off: Vec<usize> = (0..n_q)
        .map(|k| off[base + k * stride + stride - 3])
        .collect();
    let i_off: Vec<usize> = (0..n_q)
        .map(|k| off[base + k * stride + stride - 2])
        .collect();
    let fp_off: Vec<usize> = (0..n_q)
        .map(|k| off[base + k * stride + stride - 1])
        .collect();

    let lay = Layout {
        span,
        l: 1usize << LOG_ROUNDS,
        n_q,
        i0,
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
        horner_value_row: cells.n_final,
        n_final: cells.n_final,
        cells,
        ta_off,
        tchunk_cells,
        ta_depth,
        // One round: the whole opened row authenticates under the trace root.
        rounds: false,
        ra_off: Vec::new(),
        rchunk_cells: Vec::new(),
        ra_depth: 0,
        beta_op: 0,
        coeff_op,
        strip_cycles: Vec::new(),
        strip_off: 0,
        strip_k: 0,
        strip_echo_width: 0,
        strip_n_out: 0,
        strip_rows: 0,
        compose_acc_base_col: 0,
        z_op,
        deep_coeff_op,
        pub_len,
        // this path assembles the strip form, which keeps its constants
        c_pub_col: 0,
        n_pub: 0,
        n_terms,
        width_inner,
        window_inner: (n_terms - 1) / width_inner,
        ocells,
        depth,
        n_open,
        n_folds: ft.n_folds,
        log_n: ft.log_n,
        pbits,
        fbits,
        t_inner,
        n_pz: 5,
        sidecar: with_sidecar,
        pa_off,
        pchunk_cells: Vec::new(),
        pa_depth: 0,
        n_pz_absorb_chunks: 0,
        frame_len: 6,
        n_coeff: 8,
        c_periodic_col: 12,
        c_z_col: 22,
        c_coeff_col: 24,
        c_comp_z_col: 54,
        // The fixture inner argues at circuit constants: no challenge cells.
        n_chal: 0,
        c_chal_col: 0,
        c_rows: Vec::new(),
    };

    let gps = fuse(build_groups(&lay), &lay, &regions);
    let n_groups = gps.len();
    // Six shared regions, then a block of seven per query in [deep, fold,
    // auth, tauth, horner, ip, fp] order: instances of seven kinds.
    let kinds: Vec<usize> = (0..6).chain((0..n_q).flat_map(|_| 6..13)).collect();
    // The trace chain anchors to the zero leaf every chain starts from.
    let mut pins: Vec<(usize, usize, Fp)> = Vec::new();
    for q in 0..n_q {
        for j in 0..crate::crypto::stark::air::RATE {
            pins.push((j, lay.ta_off[q], Fp::ZERO));
        }
    }
    let wired = WiredMultiExt::new_kinds_bounded(regions, &kinds, gps, pins);
    let witness = wired.trace(&traces);
    Assembly {
        wired,
        witness,
        lay,
        publics: inner.publics,
        n_groups,
        region_offsets: off,
        /* The fixture has no accumulator strip; only the aggregating path does. */
        kind_bodies: body_names(false, false, false, false),
    }
}

/// The recursion over the deployed join-split: every inner query attested,
/// the inner's own constraint code recomputed over the tower by the generic
/// compose, which reads its layout from the gadget.
pub fn assemble_real(tamper: Tamper) -> Assembly {
    assemble_real_capped(tamper, usize::MAX)
}

/// The real-inner assembly with the copy constraint argued either way.
pub fn assemble_real_wired(tamper: Tamper, wiring: Wiring) -> Assembly {
    let h = inner::hasher();
    let inner = inner::shield_join_split(&h);
    assemble_over_wired(&h, inner, tamper, usize::MAX, wiring)
}

/// The real-inner assembly attesting only the first `cap` queries: the same
/// per-query machinery and every binding, over a trace a fraction of the
/// size. The wiring gate runs here; full coverage is cap >= n_queries.
pub fn assemble_real_capped(tamper: Tamper, cap: usize) -> Assembly {
    assemble_real_capped_wired(tamper, cap, Wiring::Packed)
}

/// The capped real-inner assembly with the wiring stated. `assemble_over`
/// defaults to `Packed`, right for the binding gates and wrong for a question
/// about the circuit that ships: the packed outer is 922 columns at degree 14
/// where the chained one is 704 at 10.
pub fn assemble_real_capped_wired(tamper: Tamper, cap: usize, wiring: Wiring) -> Assembly {
    let h = inner::hasher();
    let inner = inner::shield_join_split(&h);
    assemble_over_wired(&h, inner, tamper, cap, wiring)
}

/// The outer over one inner, which is what every existing caller builds.
pub fn assemble_over<A: AirExt + GenericTransition + 'static>(
    h: &Poseidon,
    inner: Inner<A>,
    tamper: Tamper,
    cap: usize,
) -> Assembly {
    assemble_over_wired(h, inner, tamper, cap, Wiring::Packed)
}

/// The same, argued either way. The emits take the chained form; the gates and
/// the reject cases stay on the packed one so a circuit that has not moved
/// keeps measuring what it measured.
pub fn assemble_over_wired<A: AirExt + GenericTransition + 'static>(
    h: &Poseidon,
    inner: Inner<A>,
    tamper: Tamper,
    cap: usize,
    wiring: Wiring,
) -> Assembly {
    let agg = combine_wired(alloc::vec![parts_over(h, inner, tamper, cap)], wiring);
    Assembly {
        wired: agg.wired,
        witness: agg.witness,
        lay: agg.lays.into_iter().next().expect("one inner, one layout"),
        publics: agg.publics,
        n_groups: agg.n_groups,
        region_offsets: agg.region_offsets,
        kind_bodies: agg.kind_bodies,
    }
}

/// The outer over several inners: one settlement proof carrying a batch. The
/// inners ride side by side over one trace, each with its own layout, so the
/// row count is the sum and the constraint set is the same one an outer over a
/// single inner proves.
pub fn assemble_many<A: AirExt + GenericTransition + 'static>(
    h: &Poseidon,
    inners: Vec<Inner<A>>,
    cap: usize,
) -> Aggregate {
    assemble_many_wired(h, inners, cap, Wiring::Packed)
}

pub fn assemble_many_wired<A: AirExt + GenericTransition + 'static>(
    h: &Poseidon,
    inners: Vec<Inner<A>>,
    cap: usize,
    wiring: Wiring,
) -> Aggregate {
    assert!(!inners.is_empty(), "a batch needs at least one inner");
    let parts = inners
        .into_iter()
        .map(|inner| parts_over(h, inner, Tamper::None, cap))
        .collect();
    combine_wired(parts, wiring)
}

/// The capped real assembly next to its raw binds, for the bind-truth probe.
pub fn build_groups_for(cap: usize) -> (Assembly, Vec<groups::Bind>) {
    let asm = assemble_real_capped(Tamper::None, cap);
    let binds = build_groups(&asm.lay);
    (asm, binds)
}

/// The binds a layout declares, for a caller that wants the wiring itself
/// rather than the groups packed over it.
pub fn binds_for(lay: &Layout) -> Vec<groups::Bind> {
    build_groups(lay)
}

pub(super) fn build_groups(lay: &Layout) -> Vec<groups::Bind> {
    let mut gps: Vec<groups::Bind> = Vec::new();
    groups::statement(lay, &mut gps);
    groups::deep(lay, &mut gps);
    groups::roots(lay, &mut gps);
    groups::fold(lay, &mut gps);
    groups::index(lay, &mut gps);
    groups::periodic(lay, &mut gps);
    groups::strip(lay, &mut gps);
    gps
}

/// Regions stack vertically over shared columns, so the addressable width is the
/// widest region rather than the sum.
fn fuse(gps: Vec<groups::Bind>, lay: &Layout, regions: &[Box<dyn AirExt>]) -> Vec<GpGroup> {
    let width = regions.iter().map(|r| r.trace_width()).max().unwrap_or(1);
    groups::collapse(&gps, lay.span, width)
}
