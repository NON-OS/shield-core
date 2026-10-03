// NONOS Operating System (AGPL-3.0-or-later)
//! The circuit: one Poseidon chain, the statement's publics region, padding.
//!
//! | region | rows | what is fixed |
//! |---|---|---|
//! | slot | (1 + depth) * 32 | row 0 lane 0 the leaf domain, lanes 6 and 7 zero |
//! | publics | 16 | its nine words, the statement |
//! | padding | 2^13 | nothing: no constraint, no pin, a zero witness |
//!
//! Row 0 of the slot is the leaf's compression, `[NONOSLV3, d0, d1, d2 | d3, K,
//! 0, 0]`, and the walked root sits in lanes 0 to 3 of the checkpoint's row,
//! `(1 + depth) * 32`. Nine copy constraints tie the statement to those cells:
//! the digest's words to lanes 1 to 4 of row 0, the kind to lane 5, the root
//! to the checkpoint. The chain's own transitions do the rest, so a proof for
//! these words is a walk from this leaf to this root and nothing else.

use super::native::hasher;
use super::{
    DEPTH, DIGEST, KIND, LEAF_DOMAIN, LOG_ROUNDS, LOG_TRACE, MASK_COLUMNS, PAD_LOG, ROOT, WORDS,
};
use crate::crypto::stark::air::{
    Air, MultiMembership, Opening, Publics, ShieldRegion, WiredMultiGen, RATE,
};
use crate::crypto::stark::field::Fp;
use crate::shield::wire::offsets;
use crate::shield::wire_class::{tie, Class};
use crate::shield::wire_pack::{groups_enforce, packed_groups, CAP};
use alloc::vec;
use alloc::vec::Vec;

const ROUNDS: usize = 1 << LOG_ROUNDS;
const SLOT: usize = 0;
const PUBLICS: usize = 1;

/// The private half: where the slot is.
#[derive(Clone, Debug)]
pub struct Witness {
    pub siblings: Vec<[Fp; RATE]>,
    pub right: Vec<bool>,
}

pub(super) struct Built {
    pub wired: WiredMultiGen,
    pub traces: Vec<Vec<Fp>>,
}

/*
 * The circuit for `words`. With a witness it is the prover's; without, the
 * verifier's shape, whose constraints, wiring and periodic columns depend on
 * nothing but the statement's length. `leaf_lanes` is what the witness
 * writes into the leaf's digest and kind lanes, so a test can write what a
 * forger would; the honest prover passes `None`, the statement's own words.
 */
pub(super) fn build(
    words: &[Fp],
    w: Option<&Witness>,
    leaf_lanes: Option<[Fp; 5]>,
) -> Option<Built> {
    if words.len() != WORDS {
        return None;
    }
    let z = Fp::ZERO;
    let dom = Fp::from_u64(LEAF_DOMAIN);
    let [d0, d1, d2, d3, k] = leaf_lanes.unwrap_or([
        words[DIGEST],
        words[DIGEST + 1],
        words[DIGEST + 2],
        words[DIGEST + 3],
        words[KIND],
    ]);
    let (siblings, right) = match w {
        Some(w) if w.siblings.len() == DEPTH && w.right.len() == DEPTH => {
            (w.siblings.clone(), w.right.clone())
        }
        Some(_) => return None,
        None => (vec![[z; RATE]; DEPTH], vec![false; DEPTH]),
    };
    let root: [Fp; RATE] = core::array::from_fn(|i| words[ROOT + i]);

    /*
     * The first step is the leaf: its second half rides as the first
     * "sibling", on the left, so row 0 holds the whole leaf preimage.
     */
    let mut sibs = Vec::with_capacity(1 + DEPTH);
    sibs.push([d3, k, z, z]);
    sibs.extend_from_slice(&siblings);
    let mut dirs = Vec::with_capacity(1 + DEPTH);
    dirs.push(false);
    dirs.extend_from_slice(&right);
    let opening = Opening {
        leaf: [dom, d0, d1, d2],
        root,
        siblings: sibs,
        directions: dirs,
    };
    let bound: Vec<(usize, usize, Fp)> = pins()
        .iter()
        .map(|&(lane, v)| (lane, 0, Fp::from_u64(v)))
        .collect();
    let slot =
        MultiMembership::new_witness_bound(hasher(), LOG_ROUNDS, vec![opening], bound).with_split();

    let publics = Publics {
        log_t: 4,
        words: words.to_vec(),
    };
    let pad = Publics {
        log_t: PAD_LOG,
        words: Vec::new(),
    };
    let traces = vec![slot.trace(), publics.trace(), pad.trace()];
    let rows = vec![Air::rows(&slot), Air::rows(&publics), Air::rows(&pad)];
    let (off, span) = offsets(&rows);

    let classes: Vec<Class> = wires()
        .iter()
        .map(|&(k, row, lane)| tie(&[(off[PUBLICS] + k, 0), (off[SLOT] + row, lane)]))
        .collect();
    let groups = packed_groups(span, &classes, CAP);
    if !groups_enforce(&groups, &classes) {
        return None;
    }

    let regions = vec![
        ShieldRegion::Membership(slot),
        ShieldRegion::Publics(publics),
        ShieldRegion::Publics(pad),
    ];
    let kinds: Vec<usize> = (0..regions.len()).collect();
    let mut wired = WiredMultiGen::new_kinds(regions, &kinds, groups)
        .with_mask(MASK_COLUMNS)
        .with_ext_challenges();
    wired.wired_mut().mark_region_public(PUBLICS);
    if Air::log_trace_len(&wired) != LOG_TRACE {
        return None;
    }
    Some(Built { wired, traces })
}

/// The row of the slot region whose lanes 0 to 3 hold the walked root: the
/// checkpoint's successor, after the leaf's compression and `DEPTH` more.
pub(crate) const CHECKPOINT_ROW: usize = (1 + DEPTH) * ROUNDS;

/// Where each statement word is wired, as `(word, row of the slot, lane)`:
/// the root to the checkpoint's lanes 0 to 3, the digest to row 0's lanes 1
/// to 4, the kind to row 0's lane 5. `lean/Shield/Attest.lean` states the same
/// table, and `attest::test` holds the two equal.
pub(crate) fn wires() -> [(usize, usize, usize); WORDS] {
    core::array::from_fn(|k| match k {
        k if k < DIGEST => (k, CHECKPOINT_ROW, k - ROOT),
        k if k < KIND => (k, 0, 1 + (k - DIGEST)),
        _ => (KIND, 0, 5),
    })
}

/// The constant pins of row 0, `(lane, value)`: the leaf domain, and zero in
/// the two lanes the leaf's second half leaves empty.
pub(crate) fn pins() -> [(usize, u64); 3] {
    [(0, LEAF_DOMAIN), (6, 0), (7, 0)]
}

/// The verifier's circuit for a statement's words.
pub fn shape(words: &[Fp]) -> Option<WiredMultiGen> {
    build(words, None, None).map(|b| b.wired)
}
