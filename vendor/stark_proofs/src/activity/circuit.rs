// NONOS Operating System (AGPL-3.0-or-later)
//! The circuit: four slot chains, four index scalars, the count, the range of
//! the gaps, the tag chain, the key commitment's chain, the statement, padding.
//!
//! A slot chain is eighteen compressions. Row 0 holds `[nk | cm]`; the
//! compression at row 32 holds `[t | position, 0, 0, 0]`, the last three lanes
//! pinned so the nullifier is a live note's; the sixteen after it walk the
//! nullifier to Λ_e. Level m's direction rides the last round row of level
//! m - 1, column `WIDTH`; level 1's is pinned to zero, so the position word
//! always sits on the right. Levels 2 to 17 are Λ_e's directions, and an index
//! scalar recomposes them into the slot's position in Λ_e.
//!
//! Wires: `nk` (row 0, lanes 0 to 3) is one value across the four slots and the
//! tag and key chains' lanes 1 to 4; each slot's walked root (the checkpoint row,
//! lanes 0 to 3) and position go to the count; the count's gaps go to the
//! range; the statement's words go to Λ_e's cells in the count, to `k`, to the
//! tag chain's week lane and its checkpoint, and to the key chain's checkpoint.
//! P is pinned and wired to nothing:
//! the statement names the payout, and the proof binds it by the transcript.

use super::native::hasher;
use super::{
    ACTIVITY_DOMAIN, COUNT, DEPTH, KEY, KEY_DOMAIN, LAMBDA, LOG_ROUNDS, LOG_TRACE, MASK_COLUMNS,
    PAD_LOG, SLOTS, TAG, WEEK, WORDS,
};
use crate::crypto::stark::air::{
    ActivityCount, Air, IndexScalar, LimbRange, MultiMembership, Opening, Publics, ShieldRegion,
    WiredMultiGen, RATE, WIDTH,
};
use crate::crypto::stark::field::Fp;
use crate::shield::wire::offsets;
use crate::shield::wire_class::{tie, Class};
use crate::shield::wire_pack::{groups_enforce, packed_groups, CAP};
use alloc::vec;
use alloc::vec::Vec;

const ROUNDS: usize = 1 << LOG_ROUNDS;
/// Compressions per slot: `nk | cm`, `t | position`, then Λ_e's levels.
pub(crate) const COMPRESSIONS: usize = 2 + DEPTH;
/// The slot chain's checkpoint row: lanes 0 to 3 hold the walked root.
pub(crate) const CHECKPOINT_ROW: usize = COMPRESSIONS * ROUNDS;
/// The row whose state is `[t | position, live, 0, 0]`.
pub(crate) const POSITION_ROW: usize = ROUNDS;

// Region order in the stack.
const INDEX: usize = SLOTS;
const COUNT_R: usize = 2 * SLOTS;
const RANGE: usize = COUNT_R + 1;
const TAG_R: usize = RANGE + 1;
const KEY_R: usize = TAG_R + 1;
const PUBLICS: usize = KEY_R + 1;

/// One slot's private half: a live spend's note commitment, its position in the
/// note tree, and its path in Λ_e; or `None` for a dead slot.
#[derive(Clone, Debug)]
pub struct Slot {
    pub cm: [Fp; RATE],
    pub note_position: u64,
    pub siblings: Vec<[Fp; RATE]>,
    pub right: Vec<bool>,
}

/// The whole private half: the key and the four slots, live ones first.
#[derive(Clone, Debug)]
pub struct Witness {
    pub nk: [Fp; RATE],
    pub slots: [Option<Slot>; SLOTS],
}

pub(super) struct Built {
    pub wired: WiredMultiGen,
    pub traces: Vec<Vec<Fp>>,
}

fn position_of(right: &[bool]) -> u64 {
    right
        .iter()
        .enumerate()
        .map(|(k, &r)| (r as u64) << k)
        .sum()
}

fn walk(start: [Fp; RATE], siblings: &[[Fp; RATE]], right: &[bool]) -> [Fp; RATE] {
    let h = hasher();
    siblings.iter().zip(right).fold(start, |node, (sib, &r)| {
        if r {
            h.compress(sib, &node)
        } else {
            h.compress(&node, sib)
        }
    })
}

/*
 * The circuit for `words`. With a witness it is the prover's; without, the
 * verifier's shape, which depends on nothing but the statement's length.
 */
pub(super) fn build(words: &[Fp], w: Option<&Witness>) -> Option<Built> {
    build_lanes(words, w, [Fp::ZERO; SLOTS])
}

/*
 * `build` with each slot's position-word lane 5 written by the caller: zero
 * for a live note, the honest prover's only value. A test writes the dead
 * domain there to model a forger counting a dummy input's nullifier.
 */
pub(super) fn build_lanes(words: &[Fp], w: Option<&Witness>, lane5: [Fp; SLOTS]) -> Option<Built> {
    if words.len() != WORDS {
        return None;
    }
    let z = Fp::ZERO;
    let nk = w.map(|w| w.nk).unwrap_or([z; RATE]);
    let blank = Slot {
        cm: [z; RATE],
        note_position: 0,
        siblings: vec![[z; RATE]; DEPTH],
        right: vec![false; DEPTH],
    };
    let slots: Vec<(bool, Slot)> = (0..SLOTS)
        .map(|j| match w.and_then(|w| w.slots[j].clone()) {
            Some(s) => (true, s),
            None => (false, blank.clone()),
        })
        .collect();
    if slots
        .iter()
        .any(|(_, s)| s.siblings.len() != DEPTH || s.right.len() != DEPTH)
    {
        return None;
    }

    let h = hasher();
    let lambda: [Fp; RATE] = core::array::from_fn(|i| words[LAMBDA + i]);
    let mut chains = Vec::with_capacity(SLOTS);
    let mut walked = [[0u64; RATE]; SLOTS];
    let mut positions = [0u64; SLOTS];
    for (j, (_, s)) in slots.iter().enumerate() {
        let pw = [Fp::from_u64(s.note_position), lane5[j], z, z];
        let t = h.compress(&nk, &s.cm);
        let nf = h.compress(&t, &pw);
        let end = walk(nf, &s.siblings, &s.right);
        walked[j] = end.map(|v| v.to_u64());
        positions[j] = position_of(&s.right);

        let mut sibs = Vec::with_capacity(COMPRESSIONS);
        sibs.push(s.cm);
        sibs.push(pw);
        sibs.extend_from_slice(&s.siblings);
        let mut dirs = Vec::with_capacity(COMPRESSIONS);
        dirs.push(false);
        dirs.push(false);
        dirs.extend_from_slice(&s.right);
        let opening = Opening {
            leaf: nk,
            root: end,
            siblings: sibs,
            directions: dirs,
        };
        chains.push(
            MultiMembership::new_witness_bound(h.clone(), LOG_ROUNDS, vec![opening], pins())
                .with_split(),
        );
    }

    let indexes: Vec<IndexScalar> = positions
        .iter()
        .map(|&p| IndexScalar::new(DEPTH, p))
        .collect();
    let count = ActivityCount {
        log_t: 1,
        live: core::array::from_fn(|j| slots[j].0),
        pos: positions,
        walked,
        root: lambda.map(|v| v.to_u64()),
    };
    let range = LimbRange {
        bits: vec![16; SLOTS - 1],
        values: (0..SLOTS - 1).map(|j| count.gap(j)).collect(),
    };

    let week = words[WEEK];
    let dom = Fp::from_u64(ACTIVITY_DOMAIN);
    let tag_root = h.compress(&[dom, nk[0], nk[1], nk[2]], &[nk[3], week, z, z]);
    let tag_open = Opening {
        leaf: [dom, nk[0], nk[1], nk[2]],
        root: tag_root,
        siblings: vec![[nk[3], week, z, z]],
        directions: vec![false],
    };
    let tag_chain = MultiMembership::new_witness_bound(
        h.clone(),
        LOG_ROUNDS,
        vec![tag_open],
        vec![(0, 0, dom), (6, 0, z), (7, 0, z)],
    )
    .with_split();

    // The key commitment: the tag's construction with the week lane pinned to zero.
    let kdom = Fp::from_u64(KEY_DOMAIN);
    let key_root = h.compress(&[kdom, nk[0], nk[1], nk[2]], &[nk[3], z, z, z]);
    let key_open = Opening {
        leaf: [kdom, nk[0], nk[1], nk[2]],
        root: key_root,
        siblings: vec![[nk[3], z, z, z]],
        directions: vec![false],
    };
    let key_chain =
        MultiMembership::new_witness_bound(h, LOG_ROUNDS, vec![key_open], key_pins()).with_split();

    // Eighteen words: 32 rows, the next power of two.
    let publics = Publics {
        log_t: 5,
        words: words.to_vec(),
    };
    let pad = Publics {
        log_t: PAD_LOG,
        words: Vec::new(),
    };

    let mut traces: Vec<Vec<Fp>> = chains.iter().map(|c| c.trace()).collect();
    traces.extend(indexes.iter().map(|i| i.trace()));
    traces.push(count.trace());
    traces.push(range.trace());
    traces.push(tag_chain.trace());
    traces.push(key_chain.trace());
    traces.push(publics.trace());
    traces.push(pad.trace());
    let mut rows: Vec<usize> = chains.iter().map(Air::rows).collect();
    rows.extend(indexes.iter().map(Air::rows));
    rows.push(Air::rows(&count));
    rows.push(Air::rows(&range));
    rows.push(Air::rows(&tag_chain));
    rows.push(Air::rows(&key_chain));
    rows.push(Air::rows(&publics));
    rows.push(Air::rows(&pad));
    let (off, span) = offsets(&rows);

    let classes = wires(&off, &indexes, &range);
    let groups = packed_groups(span, &classes, CAP);
    if !groups_enforce(&groups, &classes) {
        return None;
    }

    let mut regions: Vec<ShieldRegion> = chains.into_iter().map(ShieldRegion::Membership).collect();
    regions.extend(indexes.into_iter().map(ShieldRegion::Index));
    regions.push(ShieldRegion::Count(count));
    regions.push(ShieldRegion::Range(range));
    regions.push(ShieldRegion::Membership(tag_chain));
    regions.push(ShieldRegion::Membership(key_chain));
    regions.push(ShieldRegion::Publics(publics));
    regions.push(ShieldRegion::Publics(pad));
    /*
     * Kinds: the four slot chains share one shape, as do the four index
     * scalars; every other region is its own.
     */
    let kinds: Vec<usize> = (0..regions.len())
        .map(|r| match r {
            r if r < SLOTS => 0,
            r if r < 2 * SLOTS => 1,
            r => r - 2 * SLOTS + 2,
        })
        .collect();
    let mut wired = WiredMultiGen::new_kinds(regions, &kinds, groups)
        .with_mask(MASK_COLUMNS)
        .with_ext_challenges();
    wired.wired_mut().mark_region_public(PUBLICS);
    if Air::log_trace_len(&wired) != LOG_TRACE {
        return None;
    }
    Some(Built { wired, traces })
}

/// A slot chain's constant pins: level 1's direction is zero, and the position
/// word's last three lanes are zero, the live lane among them.
pub(crate) fn pins() -> Vec<(usize, usize, Fp)> {
    let z = Fp::ZERO;
    vec![
        (WIDTH, ROUNDS - 1, z),
        (5, POSITION_ROW, z),
        (6, POSITION_ROW, z),
        (7, POSITION_ROW, z),
    ]
}

/// The key chain's constant pins, `(column, row, value)`: the domain in lane 0,
/// zero in lanes 5 to 7, so its row 0 is `[NOXACTK1, nk0, nk1, nk2 | nk3, 0, 0, 0]`.
pub(crate) fn key_pins() -> Vec<(usize, usize, Fp)> {
    let z = Fp::ZERO;
    vec![
        (0, 0, Fp::from_u64(KEY_DOMAIN)),
        (5, 0, z),
        (6, 0, z),
        (7, 0, z),
    ]
}

/// Every copy constraint, as classes of `(row, column)` in the stacked trace.
fn wires(off: &[usize], indexes: &[IndexScalar], range: &LimbRange) -> Vec<Class> {
    let mut c = Vec::new();
    let count = off[COUNT_R];
    let word = |k: usize| (off[PUBLICS] + k, 0);

    // nk: one value across every slot's row 0 and the tag and key chains' lanes 1 to 4.
    for l in 0..RATE {
        let mut cells: Vec<(usize, usize)> = (0..SLOTS).map(|j| (off[j], l)).collect();
        cells.push((off[TAG_R], 1 + l));
        cells.push((off[KEY_R], 1 + l));
        c.push(tie(&cells));
    }
    for j in 0..SLOTS {
        // Λ_e's directions into the slot's index scalar, low bit first.
        for k in 0..DEPTH {
            let m = k + 2;
            let dir_row = off[j] + (m - 1) * ROUNDS + ROUNDS - 1;
            c.push(tie(&[
                (off[INDEX + j] + indexes[j].bit_row(k), IndexScalar::BIT),
                (dir_row, WIDTH),
            ]));
        }
        // The recomposed position, and the walked root, into the count.
        c.push(tie(&[
            (off[INDEX + j] + indexes[j].value_row(), IndexScalar::ACC),
            (count, ActivityCount::POS + j),
        ]));
        for l in 0..RATE {
            c.push(tie(&[
                (off[j] + CHECKPOINT_ROW, l),
                (count, ActivityCount::walked_col(j, l)),
            ]));
        }
    }
    // The gaps into the range.
    for j in 0..SLOTS - 1 {
        c.push(tie(&[
            (count, ActivityCount::GAP + j),
            (off[RANGE] + range.start(j), 0),
        ]));
    }
    // The statement.
    for l in 0..RATE {
        c.push(tie(&[
            word(LAMBDA + l),
            (count, ActivityCount::root_col(l)),
        ]));
        c.push(tie(&[word(TAG + l), (off[TAG_R] + ROUNDS, l)]));
        c.push(tie(&[word(KEY + l), (off[KEY_R] + ROUNDS, l)]));
    }
    c.push(tie(&[word(COUNT), (count, ActivityCount::K)]));
    c.push(tie(&[word(WEEK), (off[TAG_R], 5)]));
    c
}

/// The verifier's circuit for a statement's words.
pub fn shape(words: &[Fp]) -> Option<WiredMultiGen> {
    build(words, None).map(|b| b.wired)
}
