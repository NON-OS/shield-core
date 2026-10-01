// NONOS Operating System (AGPL-3.0-or-later)

use super::intent::publics_region;
use super::settle::Settle;
use super::stack::{stack_anchored, Anchor};
use super::terms::{balance, limb_range};
use crate::crypto::stark::air::{Poseidon, ShieldRegion, RATE};
use crate::crypto::stark::field::Fp;
use crate::shield::key::Break;
use crate::shield::note::{Note, POOL_LOG_ROUNDS};
use alloc::vec::Vec;

/// balance, four notes, two memberships, two positions, two key hierarchies,
/// two association memberships, one live gate per input, the tuple, and the
/// range region over the balance limbs.
pub const REGIONS_PER_INTENT: usize = 17;

pub struct IntentParts {
    pub regions: Vec<ShieldRegion>,
    pub traces: Vec<Vec<Fp>>,
    pub span_op: usize,
    pub leaf_col: Vec<usize>,
    pub key_span: Vec<usize>,
    pub assoc_col: Vec<usize>,
    pub depth: usize,
    pub intent: Vec<Fp>,
}

pub struct Spend<'a> {
    pub note: &'a Note,
    pub sk: [Fp; RATE],
}

#[allow(clippy::too_many_arguments)]
pub fn intent_parts(
    inputs: [Spend; 2],
    outputs: [&Note; 2],
    public_amount: u64,
    fee: u64,
    brk: Break,
    st: Settle,
    flip: Option<usize>,
    depth: usize,
) -> IntentParts {
    intent_parts_anchored(
        inputs,
        outputs,
        public_amount,
        fee,
        brk,
        st,
        flip,
        depth,
        Anchor::Planted,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn intent_parts_anchored(
    inputs: [Spend; 2],
    outputs: [&Note; 2],
    public_amount: u64,
    fee: u64,
    brk: Break,
    st: Settle,
    flip: Option<usize>,
    depth: usize,
    anchor: Anchor<'_>,
) -> IntentParts {
    let notes = [inputs[0].note, inputs[1].note, outputs[0], outputs[1]];
    let values = [
        notes[0].value,
        notes[1].value,
        notes[2].value,
        notes[3].value,
    ];
    let (air, trace) = balance(&values, public_amount, fee);
    let range = limb_range(&air, &trace);
    // The running sums after the two input legs, read from the cells the claim
    // build wires words 36 and 37 to.
    let w = crate::crypto::stark::air::Air::trace_width(&air);
    let input_sums = [trace[2 * w].value(), trace[2 * w + 4].value()];

    let h = Poseidon::new(POOL_LOG_ROUNDS, [Fp::ZERO; RATE]);
    let sks = [inputs[0].sk, inputs[1].sk];
    let mut s = stack_anchored(
        &h,
        notes,
        sks,
        brk,
        (ShieldRegion::Balance(air), trace),
        depth,
        anchor,
    );

    let (intent, pub_air) = publics_region(
        &s,
        public_amount,
        fee,
        notes[0].asset_id,
        st,
        input_sums,
        flip,
    );
    s.traces.push(pub_air.trace());
    s.regions.push(ShieldRegion::Publics(pub_air));
    s.traces.push(range.trace());
    s.regions.push(ShieldRegion::Range(range));

    IntentParts {
        regions: s.regions,
        traces: s.traces,
        span_op: s.span_op,
        leaf_col: s.leaf_col,
        key_span: s.key_span,
        assoc_col: s.assoc_col,
        depth: s.depth,
        intent,
    }
}
