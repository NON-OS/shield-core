// NONOS Operating System (AGPL-3.0-or-later)
//! The settlement outer with its regions kept by name: the inner a wrap
//! recurses over.
//!
//! `Assembly` is what every emitter and gate consumes and it holds the engine
//! as boxes. A recursion one layer up cannot use boxes, because it has to
//! recompute each region's transition over the tower and a trait object
//! offers it over one field only. These are the same assemblies with the
//! names kept, produced by the same laying and binding, so the circuit a wrap
//! verifies is byte for byte the circuit the settlement prover proves. The
//! boxed forms are built from these and never beside them.

use super::aggregate::{combine_wired_gen, Aggregate, Wiring};
use super::inner::Inner;
use super::layout::Layout;
use super::parts::{parts_over_form, ComposeForm, Parts};
use super::tamper::Tamper;
use crate::crypto::stark::air::{AirExt, GenericTransition, OuterRegion, Poseidon, WiredMultiGen};
use crate::crypto::stark::field::Fp;
use alloc::vec::Vec;

/// An aggregate whose engine keeps its regions by name.
pub struct AggregateGen<A: AirExt + GenericTransition + 'static> {
    pub gen: WiredMultiGen<OuterRegion<A>>,
    pub witness: Vec<Fp>,
    pub lays: Vec<Layout>,
    pub publics: Vec<Fp>,
    pub n_groups: usize,
    pub region_offsets: Vec<usize>,
    pub kind_bodies: Vec<(&'static str, &'static str)>,
}

/// One inner's assembly with its regions kept by name.
pub struct AssemblyGen<A: AirExt + GenericTransition + 'static> {
    pub gen: WiredMultiGen<OuterRegion<A>>,
    pub witness: Vec<Fp>,
    pub lay: Layout,
    pub publics: Vec<Fp>,
    pub n_groups: usize,
    pub region_offsets: Vec<usize>,
    pub kind_bodies: Vec<(&'static str, &'static str)>,
}

/// The boxed aggregate every existing caller consumes, built from the named
/// one so the two cannot describe different circuits.
pub(super) fn combine_wired<A: AirExt + GenericTransition + 'static>(
    parts: Vec<Parts<A>>,
    wiring: Wiring,
) -> Aggregate {
    let g = combine_wired_gen(parts, wiring, super::anchors::DEPLOYED);
    Aggregate {
        wired: g.gen.into_wired(),
        witness: g.witness,
        lays: g.lays,
        publics: g.publics,
        n_groups: g.n_groups,
        region_offsets: g.region_offsets,
        kind_bodies: g.kind_bodies,
    }
}

pub fn assemble_over_gen<A: AirExt + GenericTransition + 'static>(
    h: &Poseidon,
    inner: Inner<A>,
    tamper: Tamper,
    cap: usize,
    wiring: Wiring,
    anchors: super::anchors::Anchors,
) -> AssemblyGen<A> {
    assemble_over_gen_form(h, inner, tamper, cap, wiring, anchors, ComposeForm::Strip)
}

/// The same assembly with the composition in the form named: the wrap takes
/// `ComposeForm::Program`.
pub fn assemble_over_gen_form<A: AirExt + GenericTransition + 'static>(
    h: &Poseidon,
    inner: Inner<A>,
    tamper: Tamper,
    cap: usize,
    wiring: Wiring,
    anchors: super::anchors::Anchors,
    form: ComposeForm,
) -> AssemblyGen<A> {
    let g = combine_wired_gen(
        alloc::vec![parts_over_form(h, inner, tamper, cap, form)],
        wiring,
        anchors,
    );
    AssemblyGen {
        gen: g.gen,
        witness: g.witness,
        lay: g.lays.into_iter().next().expect("one inner, one layout"),
        publics: g.publics,
        n_groups: g.n_groups,
        region_offsets: g.region_offsets,
        kind_bodies: g.kind_bodies,
    }
}
