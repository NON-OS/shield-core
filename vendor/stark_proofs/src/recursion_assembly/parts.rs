// NONOS Operating System (AGPL-3.0-or-later)
//! One inner's regions and the data its layout needs, before any row is placed.

use super::inner::Inner;
use super::tamper::Tamper;
pub use super::cells::TranscriptCells;
use super::{auth, deep, finals, fri, periodic, points, powers, strip, transcript};
use super::compose_form::{self, ComposeMeta};
pub use super::compose_form::ComposeForm;
use crate::crypto::stark::air::{AirExt, GenericTransition, OuterRegion, Poseidon};
use crate::crypto::stark::field::{Fp, Fp2};
use alloc::sync::Arc;
use alloc::vec::Vec;

/// The generic assembler: any inner whose transition the compose gadget can
/// recompute over the tower rides the full per-query recursion. The deployed
/// join-split comes through here, and so does any compiled zkolang program,
/// which is what makes writing a new circuit in the language enough to make
/// it aggregatable. It stops at the regions; placing them is `combine`, which
/// is what lets one outer carry a batch rather than a single inner.
pub(super) fn parts_over<A: AirExt + GenericTransition + 'static>(
    h: &Poseidon,
    inner: Inner<A>,
    tamper: Tamper,
    cap: usize,
) -> Parts<A> {
    parts_over_form(h, inner, tamper, cap, ComposeForm::Strip)
}

pub(super) fn parts_over_form<A: AirExt + GenericTransition + 'static>(
    h: &Poseidon,
    inner: Inner<A>,
    tamper: Tamper,
    cap: usize,
    form: ComposeForm,
) -> Parts<A> {
    let n_q = inner.proof.queries.len().min(cap);
    let with_sidecar = inner.sidecar.is_some();

    // Row tampers stage before any region reads the sidecar; a forgery bent
    // after the regions are built tests nothing.
    let mut inner = inner;
    if with_sidecar && tamper == Tamper::BentOpenedRow {
        if let Some(sc) = inner.sidecar.as_mut() {
            sc.openings[0].row[0] = sc.openings[0].row[0] + Fp::ONE;
        }
    }
    if with_sidecar && tamper == Tamper::SwappedRowValues {
        if let Some(sc) = inner.sidecar.as_mut() {
            sc.openings[0].row.swap(0, 1);
        }
    }
    // The first permutation cell of query 0's row, bent where the second
    // round's root is the only thing that authenticates it.
    if tamper == Tamper::CopyCommitMismatch {
        if let Some(at) = inner.rounds.as_ref().map(|r| r.region_width) {
            inner.proof.queries[0].trace[at] = inner.proof.queries[0].trace[at] + Fp::ONE;
        }
    }

    // The STARK transcript first: it squeezes the seed FRI's starts from.
    let ts = transcript::stark_transcript(h, &inner);
    std::eprintln!("[asm] stark transcript");
    let ft = fri::fri_transcript(h, &inner, ts.seed);
    std::eprintln!("[asm] fri transcript");
    // A sidecar inner carries its schedule as a baked root; only the plain
    // path pays for the recompute region.
    let pz = if with_sidecar {
        None
    } else {
        Some(periodic::periodic_region(&inner, tamper))
    };
    std::eprintln!("[asm] periodic region");

    let mut q_gens: Vec<OuterRegion<A>> = Vec::new();
    let mut q_traces: Vec<Vec<Fp>> = Vec::new();
    let mut n_terms = 0usize;
    let mut deep_coeffs: Vec<Fp2> = Vec::new();
    let mut ocells: Vec<Vec<(usize, usize)>> = Vec::with_capacity(n_q);
    let mut tchunk_cells: Vec<Vec<(usize, usize)>> = Vec::with_capacity(n_q);
    let (mut depth, mut n_open, mut pbits, mut fbits) = (0usize, 0usize, 0usize, 0usize);
    let mut i0 = 0usize;
    let mut pa_depth = 0usize;
    let mut ta_depth = 0usize;
    let mut pchunk_cells: Vec<Vec<(usize, usize)>> = Vec::new();
    let mut rchunk_cells: Vec<Vec<(usize, usize)>> = Vec::new();
    let mut ra_depth = 0usize;
    for k in 0..n_q {
        let tk = if k == 0 { tamper } else { Tamper::None };
        let (dreg, dtr, nt) = deep::deep_region_k(h, &inner, k, tk);
        std::eprintln!("[asm] q{k} fold");
        let fold = fri::fri_fold_k(&inner, &ft, k, tk);
        let au = auth::auth_side_k(h, &inner, fold.ik, k, tk);
        let ta = auth::trace_auth_k(h, &inner, &au.cons_dirs, k);
        std::eprintln!("[asm] q{k} points");
        let pts = points::point_regions_k(ft.index_values[k], ft.index_values[k], ft.log_n, k, inner.grind, tk);
        let (hreg, htrace) = finals::horner_k(&inner, &ft, k);
        let pa = auth::periodic_auth_k(h, &inner, &au.cons_dirs, k);
        let ra = auth::perm_auth_k(h, &inner, &au.cons_dirs, k);
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
            pa_depth = pa.as_ref().map(|x| x.depth).unwrap_or(0);
            ra_depth = ra.as_ref().map(|x| x.depth).unwrap_or(0);
            ta_depth = ta.depth;
        }
        ocells.push(au.ocells.clone());
        tchunk_cells.push(ta.chunk_cells);
        q_gens.push(OuterRegion::Deep(Arc::new(dreg)));
        q_traces.push(dtr);
        q_gens.push(OuterRegion::Fold(Arc::new(fold.fold)));
        q_traces.push(fold.ftrace);
        q_gens.push(OuterRegion::Membership(Arc::new(au.region)));
        q_traces.push(au.trace);
        q_gens.push(OuterRegion::Membership(Arc::new(ta.region)));
        q_traces.push(ta.trace);
        // The permutation half of the row, under the second round's root. A
        // two round inner owes one of these per query: the layout strides over
        // a fixed block, so a missing region would shift every offset after it.
        assert_eq!(
            ra.is_some(),
            inner.rounds.is_some(),
            "a two round inner opens its permutation half at every query"
        );
        if let Some(x) = ra {
            rchunk_cells.push(x.chunk_cells);
            q_gens.push(OuterRegion::Membership(Arc::new(x.region)));
            q_traces.push(x.trace);
        }
        if let Some(x) = pa {
            pchunk_cells.push(x.chunk_cells);
            q_gens.push(OuterRegion::Membership(Arc::new(x.region)));
            q_traces.push(x.trace);
        }
        q_gens.push(OuterRegion::Horner(Arc::new(hreg)));
        q_traces.push(htrace);
        q_gens.push(OuterRegion::Draw(Arc::new(pts.ip)));
        q_traces.push(pts.itrace);
        q_gens.push(OuterRegion::Draw(Arc::new(pts.fp)));
        q_traces.push(pts.fptrace);
    }

    let beta_op = ts.beta_op;
    let ts_coeff_op = ts.coeff_op;
    // The coefficient vectors as regions: the powers of each squeezed alpha,
    // checked here against what the compose and DEEP regions carry.
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
    let with_rounds = inner.rounds.is_some();
    let (ft_n_folds, ft_log_n) = (ft.n_folds, ft.log_n);
    let cells = TranscriptCells::of(&ts, &ft, inner.proof.fri.final_layer.len());
    let width_inner = inner.air.trace_width();
    let pchunk_len = inner
        .sidecar
        .as_ref()
        .map(|sc| sc.periodic_z.len())
        .unwrap_or(0);
    let t_inner = inner.t as usize;
    let (z_op, deep_coeff_op) = (ts.z_op, ts.deep_coeff_op);
    let pub_len = inner.publics.len();
    let n_pz = inner.air.periodic_columns().len();
    let publics = inner.publics.clone();

    // The compose region takes the inner by value: it owns the AIR to recompute
    // the transitions during proving, so it is built last.
    // The sidecar tamper bends the claims the composition consumes and moves
    // comp_z with them, so the compose region is internally consistent and
    // lying. The transcript and deep regions keep the honest claims: exactly
    // one side of the three-way tie moves, and only the binding can catch it.
    let sidecar_root = inner.sidecar.as_ref().map(|sc| sc.root);
    let mut inner = inner;
    if with_sidecar && tamper == Tamper::PeriodicOffPoint {
        inner.ci.periodic_z[0] = inner.ci.periodic_z[0] + Fp2::ONE;
        inner.ci.comp_z = crate::crypto::stark::air::compose_ext(
            &inner.air,
            inner.g,
            inner.ci.z,
            &inner.proof.ood_frame,
            &inner.ci.periodic_z,
            &inner.ci.coeffs,
        );
    }
    /*
     * Held by name from here on. The engine gets a boxed view of each when the
     * parts are combined, so a wrap that recomputes region `i` over the tower
     * and the prover that proves region `i` are looking at one value.
     */
    let (cregs, ctrs, ss, cm) = compose_form::compose_regions(inner, form);
    let mut gens: Vec<OuterRegion<A>> = alloc::vec![OuterRegion::Transcript(Arc::new(ts.region))];
    gens.extend(cregs);
    gens.push(OuterRegion::Powers(Arc::new(cp)));
    gens.push(OuterRegion::Powers(Arc::new(dp)));
    gens.push(OuterRegion::Transcript(Arc::new(ft.transcript)));
    let mut traces: Vec<Vec<Fp>> = alloc::vec![ts.trace];
    traces.extend(ctrs);
    traces.push(cptrace);
    traces.push(dptrace);
    traces.push(ft.ttrace);
    let ComposeMeta {
        frame_len,
        n_coeff,
        c_periodic_col,
        c_z_col,
        c_coeff_col,
        c_comp_z_col,
        n_chal,
        c_chal_col,
        flat_acc,
        c_rows,
        eval_cycles,
        c_pub_col,
        n_pub,
    } = cm;
    let (cycles, acc_cols, final_row, strip_k, strip_echo_width, strip_n_out, strip_rows) =
        ss.unwrap_or_else(|| (Vec::new(), Vec::new(), 0, 0, 0, 0, 0));
    if let Some((pzregion, pztrace)) = pz {
        gens.push(OuterRegion::PeriodicZ(Arc::new(pzregion)));
        traces.push(pztrace);
    }
    gens.extend(q_gens);
    traces.extend(q_traces);

    Parts {
        gens,
        traces,
        publics,
        with_sidecar,
        n_q,
        i0,
        depth,
        n_open,
        pbits,
        fbits,
        pa_depth,
        ra_depth,
        ta_depth,
        ocells,
        tchunk_cells,
        pchunk_cells,
        rchunk_cells,
        with_rounds,
        beta_op,
        coeff_op: ts_coeff_op,
        cells,
        cycles,
        acc_cols,
        final_row,
        flat_acc,
        strip_k,
        strip_echo_width,
        strip_n_out,
        strip_rows,
        form,
        c_rows,
        eval_cycles,
        c_pub_col,
        n_pub,
        z_op,
        deep_coeff_op,
        n_terms,
        width_inner,
        t_inner,
        n_pz,
        pchunk_len,
        pub_len,
        frame_len,
        n_coeff,
        c_periodic_col,
        c_z_col,
        c_coeff_col,
        c_comp_z_col,
        n_chal,
        c_chal_col,
        n_folds: ft_n_folds,
        log_n: ft_log_n,
        sidecar_root,
    }
}

/// One inner's regions and the data its layout needs, before any row is placed.
/// Offsets are deliberately absent: they exist only once the parts are laid end
/// to end, which is what lets one outer carry several inners.
pub(super) struct Parts<A: AirExt + GenericTransition + 'static> {
    pub(super) form: ComposeForm,
    pub(super) c_rows: Vec<usize>,
    pub(super) c_pub_col: usize,
    pub(super) n_pub: usize,
    pub(super) eval_cycles: Vec<((usize, usize), (usize, usize))>,
    /// The regions by name, in stacking order. The engine's boxes are made
    /// from these when the parts are combined, never the other way round.
    pub(super) gens: Vec<OuterRegion<A>>,
    pub(super) traces: Vec<Vec<Fp>>,
    pub(super) publics: Vec<Fp>,
    pub(super) with_sidecar: bool,
    pub(super) n_q: usize,
    pub(super) i0: usize,
    pub(super) depth: usize,
    pub(super) n_open: usize,
    pub(super) pbits: usize,
    pub(super) fbits: usize,
    pub(super) pa_depth: usize,
    /// The second round's chain opening: its depth and, per query, the chunk
    /// lane cell of every permutation column value. Empty on a one round inner.
    pub(super) ra_depth: usize,
    pub(super) ta_depth: usize,
    pub(super) ocells: Vec<Vec<(usize, usize)>>,
    pub(super) tchunk_cells: Vec<Vec<(usize, usize)>>,
    pub(super) pchunk_cells: Vec<Vec<(usize, usize)>>,
    pub(super) rchunk_cells: Vec<Vec<(usize, usize)>>,
    pub(super) with_rounds: bool,
    /// The transcript operation squeezing beta, when the inner drew it.
    pub(super) beta_op: Option<usize>,
    /// The transcript operation squeezing the composition alpha's low lane.
    pub(super) coeff_op: usize,
    /// Every absorbed value and every draw the bindings reach for, by cell.
    pub(super) cells: TranscriptCells,
    pub(super) cycles: Vec<((usize, usize), strip::Home)>,
    pub(super) acc_cols: Vec<usize>,
    pub(super) final_row: usize,
    pub(super) flat_acc: Vec<usize>,
    pub(super) strip_k: usize,
    pub(super) strip_echo_width: usize,
    pub(super) strip_n_out: usize,
    pub(super) strip_rows: usize,
    pub(super) z_op: usize,
    pub(super) deep_coeff_op: usize,
    pub(super) n_terms: usize,
    pub(super) width_inner: usize,
    pub(super) t_inner: usize,
    pub(super) n_pz: usize,
    pub(super) pchunk_len: usize,
    pub(super) pub_len: usize,
    pub(super) frame_len: usize,
    pub(super) n_coeff: usize,
    pub(super) c_periodic_col: usize,
    pub(super) c_z_col: usize,
    pub(super) c_coeff_col: usize,
    pub(super) c_comp_z_col: usize,
    /// The inner's challenge cells in the compose region: how many, and the
    /// base column of the first. Zero and zero when the inner drew none.
    pub(super) n_chal: usize,
    pub(super) c_chal_col: usize,
    pub(super) n_folds: usize,
    pub(super) log_n: u32,
    pub(super) sidecar_root: Option<[Fp; crate::crypto::stark::air::RATE]>,
}
