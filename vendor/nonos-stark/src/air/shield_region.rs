// NONOS Operating System (AGPL-3.0-or-later)

//! The shield's region set as a closed enum. The wired engine holds regions
//! as boxed trait objects, which is right for layout and proving but cannot
//! carry a generic method, and the recursive verifier needs every region's
//! transition over the tower, not the base field. Naming the four concrete
//! types keeps that dispatch typed: no downcasting, and a region type outside
//! this list cannot silently lose its in-circuit recomputation.

use super::activity_count::ActivityCount;
use super::index_scalar::IndexScalar;
use super::live_gate::LiveGate;
use super::multi_membership::MultiMembership;
use super::publics::Publics;
use super::spec::AirExt;
use super::value_balance::{LimbRange, ValueBalance};
use crate::field::Felt;
use alloc::boxed::Box;
use alloc::vec::Vec;

/// Every region kind the shield stacks. Balance, ten memberships (notes,
/// pool, keys, association), two index scalars, and the publics row.
#[derive(Clone)]
// The variants differ in size because the regions do. Boxing the large ones
// would put an indirection in the transition path every row walks, which is
// the hot loop of every proof, to save stack in a vector built once.
#[allow(clippy::large_enum_variant)]
pub enum ShieldRegion {
    Balance(ValueBalance),
    Membership(MultiMembership),
    Index(IndexScalar),
    Publics(Publics),
    /// Whether a spent input has to be in the pool.
    Live(LiveGate),
    /// The balance region's limbs, rooms and carry, each below its bound.
    Range(LimbRange),
    /// The activity statement's count of distinct live spends.
    Count(ActivityCount),
}

impl ShieldRegion {
    /// The region as the trait object the wired engine stacks.
    pub fn boxed(&self) -> Box<dyn AirExt> {
        match self {
            ShieldRegion::Balance(r) => Box::new(r.clone()),
            ShieldRegion::Membership(r) => Box::new(r.clone()),
            ShieldRegion::Index(r) => Box::new(r.clone()),
            ShieldRegion::Publics(r) => Box::new(r.clone()),
            ShieldRegion::Live(r) => Box::new(r.clone()),
            ShieldRegion::Range(r) => Box::new(r.clone()),
            ShieldRegion::Count(r) => Box::new(r.clone()),
        }
    }

    /// The region seen through the trait, for layout queries before boxing.
    pub fn as_air(&self) -> &dyn AirExt {
        match self {
            ShieldRegion::Balance(r) => r,
            ShieldRegion::Membership(r) => r,
            ShieldRegion::Index(r) => r,
            ShieldRegion::Publics(r) => r,
            ShieldRegion::Live(r) => r,
            ShieldRegion::Range(r) => r,
            ShieldRegion::Count(r) => r,
        }
    }

    /// The region's transition over any field, for the recursive verifier.
    pub fn transition_gen<F: Felt>(&self, window: &[F], periodic: &[F]) -> Vec<F> {
        match self {
            ShieldRegion::Balance(r) => r.transition_gen(window, periodic),
            ShieldRegion::Membership(r) => r.transition_gen(window, periodic),
            ShieldRegion::Index(r) => r.transition_gen(window, periodic),
            ShieldRegion::Publics(r) => r.transition_gen(window, periodic),
            ShieldRegion::Live(r) => r.transition_gen(window, periodic),
            ShieldRegion::Range(r) => r.transition_gen(window, periodic),
            ShieldRegion::Count(r) => r.transition_gen(window, periodic),
        }
    }
}

/// The shield's regions as the list a recursion consults. The inherent methods
/// above are the definition; this only lets `WiredMultiGen` take them through
/// the same bound the settlement outer's regions satisfy.
impl super::gen_region::GenRegion for ShieldRegion {
    fn boxed(&self) -> Box<dyn AirExt> {
        ShieldRegion::boxed(self)
    }

    fn as_air(&self) -> &dyn AirExt {
        ShieldRegion::as_air(self)
    }

    fn transition_gen<F: Felt>(&self, window: &[F], periodic: &[F]) -> Vec<F> {
        ShieldRegion::transition_gen(self, window, periodic)
    }
}
