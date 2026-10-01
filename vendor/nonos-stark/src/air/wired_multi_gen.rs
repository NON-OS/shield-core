// NONOS Operating System (AGPL-3.0-or-later)

//! The wired engine with its regions also held by name. The boxed engine does
//! everything a prover needs; what it cannot do is hand a recursive verifier
//! each region's transition over the tower. Holding the typed list beside the
//! boxes closes that: same layout, same trace, same constraints (the boxes
//! are built from the same values the names hold) plus the one generic
//! method recursion needs.
//!
//! Generic over the region list, with the shield's as the default, because
//! the settlement outer needs the identical construction one layer up: its
//! regions held by name so a wrap can recompute them. One wrapper rather than
//! two keeps the recursion over a recursion the same code as the recursion
//! over a payment.

use super::super::field::{Felt, Fp, Fp2};
use super::compose_check_gen::GenericTransition;
use super::gen_region::GenRegion;
use super::shield_region::ShieldRegion;
use super::spec::{Air, AirExt};
use super::wired_multi_ext::{GpGroup, WiredMultiExt};
use alloc::vec::Vec;

pub struct WiredMultiGen<R: GenRegion = ShieldRegion> {
    wired: WiredMultiExt,
    gens: Vec<R>,
}

impl<R: GenRegion> WiredMultiGen<R> {
    /// One constructor, one region list: the boxes the engine stacks are made
    /// from the same values the typed list keeps, so the two views cannot
    /// disagree about what region `i` is.
    pub fn new_kinds(gens: Vec<R>, kinds: &[usize], groups: Vec<GpGroup>) -> Self {
        let boxed = gens.iter().map(|g| g.boxed()).collect();
        WiredMultiGen { wired: WiredMultiExt::new_kinds(boxed, kinds, groups), gens }
    }

    /// `n` mask columns after the products, `WiredMultiExt::with_mask`.
    pub fn with_mask(mut self, n: usize) -> Self {
        self.wired = self.wired.with_mask(n);
        self
    }

    /// The copy constraint at `Fp2` challenges, `WiredMultiExt::with_ext_challenges`.
    pub fn with_ext_challenges(mut self) -> Self {
        self.wired = self.wired.with_ext_challenges();
        self
    }

    /// An engine already built, and the typed list its boxes were made from.
    ///
    /// The settlement outer builds its engine in one place with a layout,
    /// pins and a chained permutation that this crate does not know, and its
    /// regions are shared handles rather than clones, so the boxes are made by
    /// the caller. What is checked here is the only thing that can go wrong on
    /// this path: that the list and the engine describe the same regions, one
    /// for one, same width and same rows. A list that is a region short, or
    /// in a different order, would recompute the wrong body at that index and
    /// nothing else would report it.
    pub fn from_parts(wired: WiredMultiExt, gens: Vec<R>) -> Self {
        let shapes = wired.region_shapes();
        assert_eq!(
            shapes.len(),
            gens.len(),
            "the typed region list and the engine hold different region counts"
        );
        for (i, ((w, rows), g)) in shapes.iter().zip(&gens).enumerate() {
            let a = g.as_air();
            assert!(
                a.trace_width() == *w && a.rows() == *rows,
                "region {i}: the typed list says {}x{} and the engine {w}x{rows}",
                a.trace_width(),
                a.rows()
            );
        }
        WiredMultiGen { wired, gens }
    }

    pub fn wired(&self) -> &WiredMultiExt {
        &self.wired
    }

    /// The engine, mutably, for the one thing that changes after construction:
    /// adopting the permutation challenges between the two commitment rounds.
    pub fn wired_mut(&mut self) -> &mut WiredMultiExt {
        &mut self.wired
    }

    /// The engine alone, for a caller that needs the typed list no further.
    pub fn into_wired(self) -> WiredMultiExt {
        self.wired
    }

    /// The regions by name, in stacking order, for an emitter that evaluates
    /// each body on its own rather than through the fused sum.
    pub fn regions(&self) -> &[R] {
        &self.gens
    }

    pub fn trace(&self, traces: &[Vec<Fp>]) -> Vec<Fp> {
        self.wired.trace(traces)
    }

    pub fn group_widths(&self) -> Vec<usize> {
        self.wired.group_widths()
    }

    pub fn region_degrees(&self) -> Vec<usize> {
        self.wired.region_degrees()
    }

    pub fn permutation_columns(&self) -> (usize, usize, Vec<usize>) {
        self.wired.permutation_columns()
    }

    pub fn group_params(&self) -> Vec<(Vec<usize>, Fp, Fp)> {
        self.wired.group_params()
    }

    /// Each group's permutation, for a caller asking which cells are bound
    /// rather than merely wired. See `WiredMultiExt::group_sigmas`.
    pub fn group_sigmas(&self) -> Vec<&[usize]> {
        self.wired.group_sigmas()
    }
}

impl<R: GenRegion + Send + Sync> GenericTransition for WiredMultiGen<R> {
    fn transition_gen<F: Felt>(&self, window: &[F], periodic: &[F]) -> Vec<F> {
        self.wired.transition_generic(window, periodic, |i, l, p| self.gens[i].transition_gen(l, p))
    }

    /// Beta then gamma, and only once they have been drawn. An assembled pair
    /// is part of the circuit and a verifier recomputing this AIR needs
    /// nothing handed to it.
    fn challenges_gen(&self) -> Vec<Fp> {
        if self.wired.n_challenges() == 0 {
            return Vec::new();
        }
        if self.wired.ext_challenges() {
            let (beta, gamma) = self.wired.challenges_ext();
            return alloc::vec![beta.c0, beta.c1, gamma.c0, gamma.c1];
        }
        let (beta, gamma) = self.wired.challenges();
        alloc::vec![beta, gamma]
    }

    fn transition_gen_at<F: Felt>(&self, window: &[F], periodic: &[F], chal: &[F]) -> Vec<F> {
        self.wired.transition_generic_at(window, periodic, chal, |i, l, p| {
            self.gens[i].transition_gen(l, p)
        })
    }
}

impl<R: GenRegion + Send + Sync> Air for WiredMultiGen<R> {
    fn log_trace_len(&self) -> u32 {
        self.wired.log_trace_len()
    }

    fn trace_width(&self) -> usize {
        self.wired.trace_width()
    }

    fn window_size(&self) -> usize {
        self.wired.window_size()
    }

    fn constraint_degree(&self) -> usize {
        self.wired.constraint_degree()
    }

    fn num_transition(&self) -> usize {
        self.wired.num_transition()
    }

    fn periodic_columns(&self) -> Vec<Vec<Fp>> {
        self.wired.periodic_columns()
    }

    fn transition(&self, window: &[Fp], periodic: &[Fp]) -> Vec<Fp> {
        self.wired.transition(window, periodic)
    }

    fn boundary(&self) -> Vec<(usize, usize, Fp)> {
        self.wired.boundary()
    }
}

impl<R: GenRegion + Send + Sync> AirExt for WiredMultiGen<R> {
    fn transition_ext(&self, window: &[Fp2], periodic: &[Fp2]) -> Vec<Fp2> {
        self.wired.transition_ext(window, periodic)
    }

    fn challenge_lanes(&self) -> usize {
        self.wired.challenge_lanes()
    }

    fn mask_pair(&self) -> Option<(usize, usize)> {
        self.wired.mask_pair()
    }
}
