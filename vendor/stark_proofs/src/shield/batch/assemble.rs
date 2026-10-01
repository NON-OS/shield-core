// NONOS Operating System (AGPL-3.0-or-later)

use super::uniform::price_uniform;
use crate::crypto::stark::air::{ShieldRegion, WiredMultiGen};
use crate::crypto::stark::field::Fp;
use crate::shield::join::{
    bind_classes, public_classes_at, IntentParts, Layout, REGIONS_PER_INTENT,
};
use crate::shield::wire::offsets;
use crate::shield::wire_pack::{groups_enforce, packed_groups, CAP};
use alloc::vec::Vec;

pub struct BatchProof {
    pub wired: WiredMultiGen,
    pub witness: Vec<Fp>,
    pub intents: Vec<Vec<Fp>>,
    /// Every binding this circuit carries, as emitted, and the trace span they
    /// are addressed in.
    ///
    /// Carried so a gate can check the list the assembly actually used instead
    /// of building a second one beside it and agreeing with itself. The classes
    /// are cell coordinates and cost a few words each; the packed groups are not
    /// carried, because their sigma vectors are span-sized and already live
    /// inside `wired`.
    pub classes: Vec<crate::shield::wire_class::Class>,
    pub span: usize,
}

/// The mask columns that close every inner's row. Two base columns under
/// independent `Fp2` DEEP coefficients cover every `Fp2` polynomial below the
/// FRI bound, which is what makes FRI's openings uniform. docs/12-zero-knowledge.md.
pub const MASK_COLUMNS: usize = 2;

/// Where an intent's publics region sits among its regions.
const PUBLICS_REGION: usize = 15;

/// Which rule each inner kind enforces, in kind order.
///
/// It lives beside the kind list below and is checked against it, because the
/// two are one statement written twice and the pair is only safe while they
/// cannot drift. A reader dispatching on the index alone gets no warning when a
/// kind changes body: the wrong rule is still arithmetic, it just computes a
/// different transition. Two of these are memberships and two are Poseidon
/// chains of the same width, so index and shape are both ambiguous and only the
/// name is not.
pub const KIND_BODIES: [&str; 9] = [
    "balance",
    "note_commit",
    "pool_membership",
    "index_recovery",
    "key_derivation",
    "assoc_membership",
    "publics",
    "live_gate",
    "limb_range",
];

/// Every intent's regions in one stack, each intent's own bindings emitted at its
/// base, and the clearing price tied across all of them.
/// What one intent's regions need from the layout: where its span operation
/// sits, its leaf columns, its key spans, its association columns, and its
/// depth. Named because a five field tuple in a signature is a shape rather
/// than a meaning.
type IntentMeta = (usize, Vec<usize>, Vec<usize>, Vec<usize>, usize);

pub fn assemble(parts: Vec<IntentParts>) -> BatchProof {
    assemble_with_extra_classes(parts, Vec::new())
}

/// The assembly with bindings the caller adds to the circuit's own.
///
/// `extra` exists so the wiring gate can hand the shipped assembly a class list
/// that packing cannot enforce and watch it refuse, over the bindings the
/// circuit really carries rather than over three toy ones. Production passes
/// nothing:
/// a binding a caller could add outside the bind modules is a binding no reader
/// of those modules would find.
pub fn assemble_with_extra_classes(
    parts: Vec<IntentParts>,
    extra: Vec<crate::shield::wire_class::Class>,
) -> BatchProof {
    let mut regions: Vec<ShieldRegion> = Vec::new();
    let mut traces: Vec<Vec<Fp>> = Vec::new();
    let mut intents = Vec::with_capacity(parts.len());
    let meta: Vec<IntentMeta> = parts
        .into_iter()
        .map(|p| {
            intents.push(p.intent);
            regions.extend(p.regions);
            traces.extend(p.traces);
            (p.span_op, p.leaf_col, p.key_span, p.assoc_col, p.depth)
        })
        .collect();

    let rows: Vec<usize> = regions.iter().map(|r| r.as_air().rows()).collect();
    let (off, span) = offsets(&rows);

    let mut g: Vec<crate::shield::wire_class::Class> = Vec::new();
    let mut pub_off = Vec::with_capacity(meta.len());
    for (i, (span_op, leaf_col, key_span, assoc_col, depth)) in meta.into_iter().enumerate() {
        let b = i * REGIONS_PER_INTENT;
        let lay = Layout {
            span,
            span_op,
            note: off[b + 1..b + 5].to_vec(),
            member: off[b + 5..b + 7].to_vec(),
            index: off[b + 7..b + 9].to_vec(),
            key: off[b + 9..b + 11].to_vec(),
            key_span,
            leaf_col,
            assoc: off[b + 11..b + 13].to_vec(),
            assoc_col,
            depth,
            balance: off[b],
            live: off[b + 13..b + 15].to_vec(),
            range: off[b + 16],
        };
        g.extend(bind_classes(&lay));
        g.extend(public_classes_at(&lay, off[b + PUBLICS_REGION]));
        pub_off.push(off[b + PUBLICS_REGION]);
    }
    g.extend(price_uniform(&pub_off));
    g.extend(extra);

    // Regions stack vertically and share columns, so the addressable width is the
    // widest region, not the sum.
    // An intent lays out balance, four note commitments, two pool memberships, two
    // position recoveries, two key derivations, two association memberships, then
    // its live gates, its publics and its range region. The four and the pairs are one AIR over
    // different witnesses, and every intent repeats the same seventeen, so the batch carries
    // nine kinds.
    let kinds: Vec<usize> = (0..regions.len() / REGIONS_PER_INTENT)
        .flat_map(|_| alloc::vec![0usize, 1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 7, 7, 6, 8])
        .collect();
    let n_intents = regions.len() / REGIONS_PER_INTENT;
    assert_eq!(
        KIND_BODIES.len(),
        kinds.iter().copied().max().map(|m| m + 1).unwrap_or(0),
        "the body names and the kind list must describe the same kinds"
    );
    let groups = packed_groups(span, &g, CAP);
    /*
     * Every binding class ends up on one cycle of the group that carries it,
     * which is what forces its cells equal. Checked on the built groups rather
     * than assumed from a disjointness precondition on the raw classes, so a
     * class that packing failed to enforce is caught here instead of passing
     * silently.
     *
     * Not a debug assertion. This crate is built and tested under --release
     * everywhere: ci.yml, soundness.yml, the release tier and every emitter, so
     * a debug_assert here ran nowhere at all. `groups_enforce` had three unit
     * tests over three toy classes and was never once pointed at the hundred
     * and ninety six of the shipped circuit, which is the same shape as the
     * half-selector that was inert while all four of its own gates passed.
     *
     * It costs one walk of each class's cycle at circuit build, which is not
     * per row and not per query, against the failure it catches: a dropped
     * binding leaves every other binding holding and the proof verifying, and
     * an unbound membership is how a second input came to be unheld.
     */
    assert!(
        groups_enforce(&groups, &g),
        "a binding class is not enforced by its group"
    );
    let mut wired = WiredMultiGen::new_kinds(regions, &kinds, groups)
        .with_mask(MASK_COLUMNS)
        .with_ext_challenges();
    // v2: every kind's periodic slots on one set of columns (docs/17).
    #[cfg(feature = "v2")]
    wired.wired_mut().overlay_periodic();
    /*
     * One intent is a statement a chain can verify directly, and its publics
     * region's boundaries are that statement: marked as the pins a verifier
     * reads from calldata. A batch's statement is its intents' words end to
     * end across several regions, which only a recursion reads.
     */
    if n_intents == 1 {
        wired.wired_mut().mark_region_public(PUBLICS_REGION);
    }
    let witness = wired.trace(&traces);
    BatchProof {
        wired,
        witness,
        intents,
        classes: g,
        span,
    }
}
