// NONOS Operating System (AGPL-3.0-or-later)

use super::assoc::{assoc_membership, assoc_membership_against};
use super::keys::key_hierarchies;
use super::notes::note_regions;
use super::pool::{pool_membership, pool_membership_against, Witnessed};
use crate::crypto::stark::air::{LiveGate, Poseidon, ShieldRegion, LANES, RATE};
use crate::crypto::stark::field::Fp;
use crate::shield::key::{Break, DEAD_DOMAIN};
use crate::shield::note::Note;
use alloc::vec::Vec;

/// A digest as the raw limbs a region row carries.
fn lanes(d: [Fp; RATE]) -> [u64; LANES] {
    let mut out = [0u64; LANES];
    for (o, v) in out.iter_mut().zip(d.iter()) {
        *o = v.value();
    }
    out
}

pub struct Stack {
    pub regions: Vec<ShieldRegion>,
    pub traces: Vec<Vec<Fp>>,
    pub span_op: usize,
    pub leaf_col: Vec<usize>,
    pub key_span: Vec<usize>,
    pub root: [Fp; RATE],
    pub nf: [[Fp; RATE]; 2],
    pub out_cm: [[Fp; RATE]; 2],
    pub assoc_root: [Fp; RATE],
    pub assoc_col: Vec<usize>,
    pub depth: usize,
}

/// Where the two input notes are proven to live.
///
/// `Planted` builds a tree holding only those notes and proves against its own
/// root, which is what the fixtures want and what no deployment can accept.
/// `Published` proves against a root the pool already published, with the
/// openings supplied by whoever read the tree.
pub enum Anchor<'a> {
    Planted,
    Published {
        openings: [&'a Witnessed; 2],
        root: [Fp; RATE],
        /// The association set, when the registry supplies it. `None` keeps
        /// the planted set, which is what the fixtures use and what no
        /// settlement can accept: `settleBatch` refuses an association root
        /// its registry never issued, and a prover-planted root is never one
        /// of those.
        assoc: Option<AssocAnchor<'a>>,
    },
}

/// A published association set: the openings of the two spent notes and the
/// root the registry holds.
pub struct AssocAnchor<'a> {
    pub openings: [&'a Witnessed; 2],
    pub root: [Fp; RATE],
}

/// Region order: balance, four notes, two memberships, two key hierarchies. The
/// bindings address regions by that order.
#[allow(clippy::too_many_arguments)]
pub fn stack_anchored(
    h: &Poseidon,
    notes: [&Note; 4],
    sks: [[Fp; RATE]; 2],
    brk: Break,
    bal: (ShieldRegion, Vec<Fp>),
    depth: usize,
    anchor: Anchor<'_>,
) -> Stack {
    let n = note_regions(notes, brk);
    let span_op = n.span_op;
    let cms = n.cms.clone();
    let mut regions: Vec<ShieldRegion> = alloc::vec![bal.0];
    let mut traces = alloc::vec![bal.1];
    regions.extend(n.regions);
    traces.extend(n.traces);

    let p = match anchor {
        Anchor::Planted => pool_membership(h, &[cms[0], cms[1]], depth),
        Anchor::Published { openings, root, .. } => {
            /*
             * A path shorter or longer than the tree walks to a root at the
             * wrong height, and the walk would still be honest arithmetic, so
             * it would not fail as a constraint. It fails here instead, where
             * the caller can still see which input was wrong.
             */
            for (i, o) in openings.iter().enumerate() {
                assert_eq!(
                    o.siblings.len(),
                    depth,
                    "input {i} opening is {} levels against a depth {depth} tree",
                    o.siblings.len()
                );
            }
            pool_membership_against(h, &[cms[0], cms[1]], openings, root)
        }
    };
    let leaves = p.leaves.clone();
    let leaf_col = p.leaf_col.clone();
    regions.extend(p.regions);
    traces.extend(p.traces);

    // The position each membership authenticated, recovered as the scalar the
    // nullifier hashes. Placed after membership so a reader meets the position
    // where it is proven, then where it is consumed.
    let ix = super::index::positions(&leaves, depth, brk);
    regions.extend(ix.regions);
    traces.extend(ix.traces);

    /*
     * Liveness is decided here, once, because two regions read it: the gate
     * that makes membership conditional, and the key hierarchy, whose fourth
     * compression absorbs a different word for a dummy so the nullifier the
     * pool burns for it cannot be a real one.
     *
     * It is decided in the field because that is where the gate's constraint
     * looks: the gate recomposes `lo + hi * 2^32`, so a note worth exactly p is
     * worth zero there, and deciding from the u64 would declare it live and
     * then fail `live = value * inv`. `DeadCarrier` cuts the tie so the forgery
     * can be built at all.
     */
    let live: [bool; 2] = core::array::from_fn(|i| {
        Fp::from_u64(notes[i].value) != Fp::ZERO && !(i == 1 && brk == Break::DeadCarrier)
    });

    let k = key_hierarchies(sks, &[cms[0], cms[1]], &leaves, live, brk);
    let key_span = k.key_span.clone();
    let nfs = k.nf;
    regions.extend(k.regions);
    traces.extend(k.traces);

    /*
     * The association set, published when the caller has one. The planted
     * form builds its own three-pad set and returns the root it computed,
     * which is a root no registry has issued, so a spend proved against it
     * is refused on chain before anything else about it is examined.
     */
    let a = match &anchor {
        Anchor::Published {
            assoc: Some(aa), ..
        } => assoc_membership_against(h, &[cms[0], cms[1]], aa.openings, aa.root),
        _ => assoc_membership(
            h,
            &[cms[0], cms[1]],
            &[900, 901, 902],
            brk == Break::Unlisted,
            depth,
        ),
    };
    regions.extend(a.regions);
    traces.extend(a.traces);

    /*
     * One live gate per input, last, so the region order stays append only. The
     * gate holds each input's walked roots against the published ones and only
     * when the input is live, which is the equality the binder used to emit
     * unconditionally, and it holds the lane of the position word that says so.
     */
    let limbs = |v: u64| [v & 0xFFFF_FFFF, v >> 32];
    // `inv` returns zero at zero, which is what a dummy needs.
    let inverse = |v: u64| Fp::from_u64(v).inv().value();
    for (i, note) in notes.iter().take(2).enumerate() {
        let g = LiveGate {
            log_t: 1,
            live: live[i],
            value: limbs(note.value),
            inv: inverse(note.value),
            walked_note: lanes(p.walked[i]),
            note_root: lanes(p.root),
            walked_assoc: lanes(a.walked[i]),
            assoc_root: lanes(a.root),
            dead: if live[i] { 0 } else { DEAD_DOMAIN },
            dead_domain: DEAD_DOMAIN,
        };
        traces.push(g.trace());
        regions.push(ShieldRegion::Live(g));
    }

    Stack {
        regions,
        traces,
        span_op,
        leaf_col,
        key_span,
        root: p.root,
        nf: [nfs[0], nfs[1]],
        out_cm: [cms[2], cms[3]],
        assoc_root: a.root,
        assoc_col: a.leaf_col,
        depth,
    }
}
