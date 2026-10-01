// NONOS Operating System (AGPL-3.0-or-later)
//! Region 1 in generic form: the out-of-domain composition recomputed from the
//! inner AIR's own transition code at `Ext2<F>`, so nothing is transcribed by
//! hand. The region takes the AIR by value and owns it while proving.

use super::inner::Inner;
use crate::crypto::stark::air::{AirExt, ComposeCheckGen, GenericTransition};
use crate::crypto::stark::field::Fp;
use alloc::vec::Vec;

/// One region for any inner whose transition the recursion can recompute over
/// the tower, so the generic compose cannot fork per inner.
pub fn compose_gen_region<A: AirExt + GenericTransition>(
    inner: Inner<A>,
) -> (ComposeCheckGen<A>, Vec<Fp>) {
    let words = inner.publics.clone();
    let region = ComposeCheckGen::new_witness(
        inner.air,
        inner.proof.ood_frame,
        inner.ci.periodic_z,
        inner.ci.coeffs,
        inner.ci.z,
        inner.ci.comp_z,
        inner.g,
    )
    // The program form records this region as a tape, and a constant in it is
    // a periodic column of the outer. The words come in as cells instead.
    .with_public_words(&words);
    let trace = region.trace();
    (region, trace)
}

/// The strip form: the recompute lives in the strip region, and this region
/// pins each out to its acc cell plus the statement part.
pub fn compose_gen_region_strip<A: AirExt + GenericTransition>(
    inner: Inner<A>,
    stmt: Vec<crate::crypto::stark::air::OutStatement>,
) -> (ComposeCheckGen<A>, Vec<Fp>) {
    let region = ComposeCheckGen::new_witness(
        inner.air,
        inner.proof.ood_frame,
        inner.ci.periodic_z,
        inner.ci.coeffs,
        inner.ci.z,
        inner.ci.comp_z,
        inner.g,
    )
    .into_strip(stmt);
    let trace = region.trace();
    (region, trace)
}
