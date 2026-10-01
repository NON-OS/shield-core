// NONOS Operating System (AGPL-3.0-or-later)

//! The settlement outer's regions held by name, so a recursion can be built
//! over a circuit that already contains one.
//!
//! Fourteen kinds, nine bodies. The four authentication kinds are one Merkle
//! chain that knows nothing about what it authenticates, the two transcripts
//! are one sponge, the two index kinds are one draw decomposition. What differs
//! between kinds of one body is arity and width, and both are fields of the
//! emitted kind map rather than facts a port has to know.
//!
//! Every variant is shared rather than cloned. The compose region owns the
//! inner AIR it recomputes and that AIR is not cheaply copyable, so the boxed
//! view the engine stacks and the typed view a recursion evaluates are two
//! handles on one allocation. `AirExt` carries `Send` for exactly this: a
//! shared handle is only `Sync` if what it points at can cross a thread.

use super::compose_check_gen::{ComposeCheckGen, GenericTransition};
use super::compose_strip::ComposeStrip;
use super::deep_check_ext::DeepCheckExt;
use super::gen_region::GenRegion;
use super::alpha_powers::AlphaPowers;
use super::horner::Horner;
use super::index_draw::IndexDraw;
use super::line_eval::LineEval;
use super::multi_membership::MultiMembership;
use super::periodic_z::PeriodicZ;
use super::spec::AirExt;
use super::trace_fold_ext::TraceFoldExt;
use super::transcript_check::TranscriptCheck;
use crate::field::Felt;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

pub enum OuterRegion<A: AirExt + GenericTransition + 'static> {
    Transcript(Arc<TranscriptCheck>),
    Compose(Arc<ComposeCheckGen<A>>),
    Strip(Arc<ComposeStrip>),
    /// The composition over the outer as a straight-line program: the
    /// wrap's form, three columns wide.
    Eval(Arc<LineEval>),
    /// The powers of one squeezed challenge, standing in for a coefficient
    /// per term: the wrap's transcript squeezes once per vector.
    Powers(Arc<AlphaPowers>),
    /// Only on the plain path: a sidecar inner carries its schedule as a baked
    /// root and never builds this region.
    PeriodicZ(Arc<PeriodicZ>),
    Deep(Arc<DeepCheckExt>),
    Fold(Arc<TraceFoldExt>),
    Membership(Arc<MultiMembership>),
    /// The final polynomial at one query's last point.
    Horner(Arc<Horner>),
    /// A drawn index: the squeezed element decomposed and walked to its point.
    Draw(Arc<IndexDraw>),
}

impl<A: AirExt + GenericTransition + 'static> GenRegion for OuterRegion<A> {
    fn boxed(&self) -> Box<dyn AirExt> {
        match self {
            OuterRegion::Transcript(r) => Box::new(r.clone()),
            OuterRegion::Compose(r) => Box::new(r.clone()),
            OuterRegion::Strip(r) => Box::new(r.clone()),
            OuterRegion::Eval(r) => Box::new(r.clone()),
            OuterRegion::Powers(r) => Box::new(r.clone()),
            OuterRegion::PeriodicZ(r) => Box::new(r.clone()),
            OuterRegion::Deep(r) => Box::new(r.clone()),
            OuterRegion::Fold(r) => Box::new(r.clone()),
            OuterRegion::Membership(r) => Box::new(r.clone()),
            OuterRegion::Horner(r) => Box::new(r.clone()),
            OuterRegion::Draw(r) => Box::new(r.clone()),
        }
    }

    fn as_air(&self) -> &dyn AirExt {
        match self {
            OuterRegion::Transcript(r) => r.as_ref(),
            OuterRegion::Compose(r) => r.as_ref(),
            OuterRegion::Strip(r) => r.as_ref(),
            OuterRegion::Eval(r) => r.as_ref(),
            OuterRegion::Powers(r) => r.as_ref(),
            OuterRegion::PeriodicZ(r) => r.as_ref(),
            OuterRegion::Deep(r) => r.as_ref(),
            OuterRegion::Fold(r) => r.as_ref(),
            OuterRegion::Membership(r) => r.as_ref(),
            OuterRegion::Horner(r) => r.as_ref(),
            OuterRegion::Draw(r) => r.as_ref(),
        }
    }

    fn transition_gen<F: Felt>(&self, window: &[F], periodic: &[F]) -> Vec<F> {
        match self {
            OuterRegion::Transcript(r) => r.transition_gen(window, periodic),
            OuterRegion::Compose(r) => r.transition_gen(window, periodic),
            OuterRegion::Strip(r) => r.transition_gen(window, periodic),
            OuterRegion::Eval(r) => r.transition_gen(window, periodic),
            OuterRegion::Powers(r) => r.transition_gen(window, periodic),
            OuterRegion::PeriodicZ(r) => r.transition_gen(window, periodic),
            OuterRegion::Deep(r) => r.transition_gen(window, periodic),
            OuterRegion::Fold(r) => r.transition_gen(window, periodic),
            OuterRegion::Membership(r) => r.transition_gen(window, periodic),
            OuterRegion::Horner(r) => r.transition_gen(window, periodic),
            OuterRegion::Draw(r) => r.transition_gen(window, periodic),
        }
    }
}
