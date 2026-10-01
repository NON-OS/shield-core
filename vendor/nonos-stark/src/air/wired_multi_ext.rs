// NONOS Operating System (AGPL-3.0-or-later)

//! The money-grade wired engine with the copy constraint split across several
//! grand-product columns. Routing every shared value through one permutation makes
//! that constraint's degree the number of wired columns, which for a large assembly
//! blows up the evaluation domain and the on-chain composition check. Splitting the
//! bindings into independent groups, one grand-product column each, keeps every
//! constraint at the size of its group plus a constant, so the AIR degree stays at
//! the region maximum. Same soundness, same bindings, cheap to verify. Layout,
//! region transitions, and each group's product come from `fusion`.

use super::super::field::{Fp, Fp2};
use super::chained_product;
use super::fusion::Stack;
use super::spec::AirExt;
use alloc::boxed::Box;
use alloc::vec::Vec;

mod fill;
mod pair;
mod product;
mod publics;
mod traits;

/// One copy-constraint group: the columns it binds, the permutation over their
/// cells, and its challenges. Each group is an independent grand product.
pub struct GpGroup {
    pub wired_cols: Vec<usize>,
    pub sigma: Vec<usize>,
    pub beta: Fp,
    pub gamma: Fp,
}

pub struct WiredMultiExt {
    regions: Vec<Box<dyn AirExt>>,
    stack: Stack,
    groups: Vec<GpGroup>,
    /*
     * Argue the single group in `groups` as one product chained through
     * intermediate accumulators, instead of one product per group. Packed
     * spends a sigma column per column per group, chained one per column: on
     * the settlement outer, 2,025 against 368. Same permutation either way, so
     * this is cost only, and the packed path is left alone so a circuit that
     * has not moved emits what it emitted.
     */
    chained: bool,
    /// The identity column `r * k + j` depends only on a group's width, and the
    /// product selector is the same column for every group, so both are emitted
    /// once and shared. Only sigma is per group.
    row_idx: usize,
    sig_base: Vec<usize>,
    sel_idx: usize,
    region_transitions: usize,
    /// Assembly-injected constant pins: cells the statement fixes that no
    /// region owns, like a baked commitment root a sidecar authenticates
    /// against. The witness-form regions deliberately pin nothing, so
    /// constants that anchor them enter here.
    extra_boundary: Vec<(usize, usize, Fp)>,
    /// How many of the last extra pins carry the statement's public words.
    /// Their values are read from the publics a verifier is handed, never
    /// from the circuit. `publics.rs`.
    public_pins: usize,
    /// Set once the challenges are drawn. A drawn pair belongs to the proof, so
    /// a verifier recomputing this AIR must be handed it rather than carry it.
    drawn: bool,
    /// Columns after the products that no constraint reads. A hiding prover
    /// fills them with a random polynomial of full FRI degree, which enters
    /// DEEP like any column and masks everything FRI opens. `with_mask`.
    mask: usize,
    /// The copy constraint argued at challenges in `Fp2`: each running
    /// product is two columns and each group two constraints, the components
    /// of one `Fp2` relation. `with_ext_challenges`.
    ext: bool,
    /// The `X` components of beta and gamma, zero unless `ext`.
    beta_x: Fp,
    gamma_x: Fp,
    /// A region whose boundaries are the statement's public words, for a
    /// circuit a chain verifies directly: their indices in `Air::boundary`.
    /// `publics::mark_region_public`.
    region_pins: Option<core::ops::Range<usize>>,
}

impl WiredMultiExt {
    /// The shared selector, row-identity and per-group sigma column indices,
    /// for a verifier that reads the permutation from the committed periodic
    /// columns instead of hand-deriving it.
    pub fn permutation_columns(&self) -> (usize, usize, Vec<usize>) {
        (self.sel_idx, self.row_idx, self.sig_base.clone())
    }

    /// Each group's wired columns and challenges, the constraint-side half of
    /// what `permutation_columns` locates.
    pub fn group_params(&self) -> Vec<(Vec<usize>, Fp, Fp)> {
        self.groups
            .iter()
            .map(|g| (g.wired_cols.clone(), g.beta, g.gamma))
            .collect()
    }

    /// Width of each running product: the widest sets the degree.
    pub fn group_widths(&self) -> Vec<usize> {
        self.groups.iter().map(|g| g.wired_cols.len()).collect()
    }

    /// Each group's permutation, for a caller asking which cells the wiring
    /// actually binds. A slot the permutation fixes is in no class: its
    /// numerator and denominator factors are the same value and cancel, so
    /// moving that cell breaks nothing and pays for nothing.
    pub fn group_sigmas(&self) -> Vec<&[usize]> {
        self.groups.iter().map(|g| g.sigma.as_slice()).collect()
    }

    /// Set the point the copy constraint is argued at.
    ///
    /// These belong to the proof, not the circuit: a grand product only argues
    /// anything when the prover could not have built its trace against the
    /// point. They are circuit constants today, which is what this is for. The
    /// prover calls it between committing the region columns and building the
    /// permutation columns, and until it does, the assembled default is a
    /// value the prover knows in advance.
    pub fn set_challenges(&mut self, beta: Fp, gamma: Fp) {
        for group in self.groups.iter_mut() {
            group.beta = beta;
            group.gamma = gamma;
        }
        self.drawn = true;
    }

    /// How many challenge values a caller recomputing this transition supplies:
    /// beta then gamma, or with `ext` beta's two components then gamma's. Zero
    /// until they are drawn.
    pub fn n_challenges(&self) -> usize {
        if self.drawn {
            if self.ext {
                4
            } else {
                2
            }
        } else {
            0
        }
    }

    /// The challenges in force, for a verifier that has to agree about them.
    pub fn challenges(&self) -> (Fp, Fp) {
        self.groups
            .first()
            .map(|g| (g.beta, g.gamma))
            .unwrap_or((Fp::ZERO, Fp::ZERO))
    }

    /// Where the permutation columns begin, which is where the two commitment
    /// rounds split: regions below, whatever the challenges produce above.
    pub fn region_width(&self) -> usize {
        self.stack.width
    }

    /// Per region degree. The AIR takes the larger of this and the widest product,
    /// so moving one alone moves nothing.
    pub fn region_degrees(&self) -> Vec<usize> {
        self.regions.iter().map(|r| r.constraint_degree()).collect()
    }

    /// Per region width and row count, in stacking order, so a typed region
    /// list built beside this engine can be held to describe the same regions.
    pub fn region_shapes(&self) -> Vec<(usize, usize)> {
        self.regions.iter().map(|r| (r.trace_width(), r.rows())).collect()
    }

    /*
     * Per kind, in kind order: where the kind's periodic values begin, how many
     * it owns, how many constraint indices its body writes, how many regions
     * run it, and how wide one of those regions is. A verifier evaluating the transition at z needs the first
     * two to slice the periodic vector and the third to know how far into the
     * shared constraint vector that kind reaches; none of the three is
     * recoverable from the trace, and the widest arity here is the overlap
     * width, so a reader that has this does not have to be told it separately.
     * The width is here because a consumer recomputing a kind's transition has
     * to slice the window before it can evaluate anything.
     */
    pub fn kind_map(&self) -> Vec<(usize, usize, usize, usize, usize)> {
        let sel = self.stack.n_kinds;
        (0..self.stack.n_kinds)
            .map(|k| {
                let first = self.stack.kind_first[k];
                let instances = self.stack.kind_of.iter().filter(|&&j| j == k).count();
                (
                    sel + self.stack.kind_slot[k],
                    self.stack.kind_slots[k],
                    self.regions[first].num_transition(),
                    instances,
                    self.regions[first].trace_width(),
                )
            })
            .collect()
    }

    pub fn new(regions: Vec<Box<dyn AirExt>>, groups: Vec<GpGroup>) -> WiredMultiExt {
        let kinds: Vec<usize> = (0..regions.len()).collect();
        WiredMultiExt::new_kinds(regions, &kinds, groups)
    }

    /// `kinds[i]` names region `i`'s kind. Instances of one kind must run equal
    /// constraints over an equal periodic pattern; they then share one selector
    /// and one set of columns instead of carrying an identical copy each.
    pub fn new_kinds(
        regions: Vec<Box<dyn AirExt>>,
        kinds: &[usize],
        groups: Vec<GpGroup>,
    ) -> WiredMultiExt {
        WiredMultiExt::new_kinds_bounded(regions, kinds, groups, Vec::new())
    }

    /// `new_kinds` with constant pins the statement adds on top of the
    /// regions' own boundaries.
    pub fn new_kinds_bounded(
        regions: Vec<Box<dyn AirExt>>,
        kinds: &[usize],
        groups: Vec<GpGroup>,
        extra_boundary: Vec<(usize, usize, Fp)>,
    ) -> WiredMultiExt {
        WiredMultiExt::build(regions, kinds, groups, extra_boundary, false)
    }

    /// The same assembly with the wiring argued as one chained permutation.
    ///
    /// `perm` comes from `recursion_assembly::groups::single`, which has
    /// already been checked to have the declared classes as its cycles. It
    /// rides in the group carrier because that is what it is: one product, one
    /// sigma run, one pair of challenges. Only the accumulator count and the
    /// way the lanes chain differ.
    pub fn new_kinds_chained(
        regions: Vec<Box<dyn AirExt>>,
        kinds: &[usize],
        perm: GpGroup,
        extra_boundary: Vec<(usize, usize, Fp)>,
    ) -> WiredMultiExt {
        WiredMultiExt::build(regions, kinds, alloc::vec![perm], extra_boundary, true)
    }

    fn build(
        regions: Vec<Box<dyn AirExt>>,
        kinds: &[usize],
        groups: Vec<GpGroup>,
        extra_boundary: Vec<(usize, usize, Fp)>,
        chained: bool,
    ) -> WiredMultiExt {
        assert!(
            !chained || groups.len() == 1,
            "the chained argument is one permutation over every wired column, \
             so it takes exactly one group and was given {}",
            groups.len()
        );
        let stack = Stack::of_kinds(&regions, kinds);
        // A kind runs one instance's constraints over every instance's rows, so
        // instances that are not the same AIR swap one region's rules for
        // another's. The caller declares kinds, so check the caller.
        for (i, &k) in kinds.iter().enumerate() {
            let rep = stack.kind_first[k];
            assert!(
                regions[i].trace_width() == regions[rep].trace_width()
                    && regions[i].window_size() == regions[rep].window_size()
                    && regions[i].log_trace_len() == regions[rep].log_trace_len()
                    && regions[i].num_transition() == regions[rep].num_transition()
                    && regions[i].constraint_degree() == regions[rep].constraint_degree()
                    && regions[i].periodic_columns() == regions[rep].periodic_columns(),
                "region {i} is declared kind {k} but does not match instance {rep}"
            );
        }
        let region_slots = stack.kind_slot.last().copied().unwrap_or(0)
            + stack
                .kind_first
                .last()
                .map(|&i| regions[i].periodic_columns().len())
                .unwrap_or(0);
        let base = stack.n_kinds + region_slots;
        let sel_idx = base;
        // The identity a cell is compared against is r * k + j, which is linear in
        // the row, so one column of r serves every group and lane. It used to be a
        // column per lane per distinct width: 21 columns on the recursion, each the
        // full trace length, to carry what multiply and add already give.
        let row_idx = base + 1;
        let mut s = base + 2;
        let mut sig_base = Vec::with_capacity(groups.len());
        for grp in &groups {
            sig_base.push(s);
            s += grp.wired_cols.len();
        }
        for (g, grp) in groups.iter().enumerate() {
            let k = grp.wired_cols.len();
            stack.assert_bound_below_close(&grp.sigma, k, &alloc::format!("group {g}"));
        }
        let mut region_transitions = 0usize;
        for region in &regions {
            region_transitions = region_transitions.max(region.num_transition());
        }
        WiredMultiExt {
            regions,
            stack,
            groups,
            row_idx,
            sig_base,
            sel_idx,
            region_transitions,
            extra_boundary,
            public_pins: 0,
            chained,
            drawn: false,
            mask: 0,
            ext: false,
            beta_x: Fp::ZERO,
            gamma_x: Fp::ZERO,
            region_pins: None,
        }
    }

    /// Overlay every kind's periodic slots on one set of columns
    /// (`Stack::overlay`), and move the wiring's periodic columns down to
    /// follow them. A different circuit from the stacked one: its periodic
    /// root and parameter identity differ, and nothing built without this
    /// changes. For v2.
    pub fn overlay_periodic(&mut self) {
        self.stack.overlay();
        let base = self.stack.n_kinds + self.stack.region_slots();
        self.sel_idx = base;
        self.row_idx = base + 1;
        let mut s = base + 2;
        for (g, grp) in self.groups.iter().enumerate() {
            self.sig_base[g] = s;
            s += grp.wired_cols.len();
        }
    }

    /// Argue the copy constraint at challenges drawn in `Fp2`.
    ///
    /// Over `Fp` a grand product over `t` rows and `k` wired columns fails to
    /// catch a wrong wiring with probability up to `t k / p`, about `2^-45`
    /// for the inner, and a prover may retry with a new commitment. Over `Fp2`
    /// the bound is `t k / p^2`. The packed form only: the chained form serves
    /// the settlement outer, whose challenges a Keccak transcript on chain
    /// replays in `Fp`.
    pub fn with_ext_challenges(mut self) -> WiredMultiExt {
        assert!(!self.chained, "extension challenges are for the packed form");
        self.ext = true;
        self
    }

    /// Whether the copy constraint is argued in `Fp2`.
    pub fn ext_challenges(&self) -> bool {
        self.ext
    }

    /// Adopt challenges drawn in `Fp2`. The `X` components are dropped unless
    /// the AIR was built with `with_ext_challenges`.
    pub fn set_challenges_ext(&mut self, beta: Fp2, gamma: Fp2) {
        self.set_challenges(beta.c0, gamma.c0);
        if self.ext {
            self.beta_x = beta.c1;
            self.gamma_x = gamma.c1;
        }
    }

    /// The challenges in force, as `Fp2`.
    pub fn challenges_ext(&self) -> (Fp2, Fp2) {
        let (b, g) = self.challenges();
        (Fp2::new(b, self.beta_x), Fp2::new(g, self.gamma_x))
    }

    /// `n` mask columns after the products. They carry no constraint and no
    /// wiring, so they change what DEEP combines and nothing a constraint sees.
    pub fn with_mask(mut self, n: usize) -> WiredMultiExt {
        self.mask = n;
        self
    }

    /// How many mask columns close the row.
    pub fn mask_columns(&self) -> usize {
        self.mask
    }

    /// How many running-product columns the argument needs. The packed form
    /// keeps one per group; the chained form keeps one per accumulator step,
    /// with the last holding the running product itself.
    ///
    /// Public because an emitter has to say where those columns and their lanes
    /// begin, and the group count is only the same number in the packed form.
    /// A layout that used the group count under chained wiring put both bases
    /// fifty seven off.
    pub fn product_columns(&self) -> usize {
        if self.chained {
            chained_product::blocks(self.groups[0].wired_cols.len())
        } else if self.ext {
            2 * self.groups.len()
        } else {
            self.groups.len()
        }
    }

    fn stride(&self) -> usize {
        self.stack.width + self.product_columns() + self.mask
    }

    fn closes_at(&self) -> usize {
        self.stack.closes_at()
    }

    pub fn wired_columns(&self) -> Vec<usize> {
        let mut c: Vec<usize> = self
            .groups
            .iter()
            .flat_map(|g| g.wired_cols.iter().copied())
            .collect();
        c.sort_unstable();
        c.dedup();
        c
    }
}
