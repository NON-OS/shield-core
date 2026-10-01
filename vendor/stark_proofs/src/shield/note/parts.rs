// NONOS Operating System (AGPL-3.0-or-later)

use super::limbs::{quads, Note, POOL_LOG_ROUNDS};
use crate::crypto::stark::air::{MultiMembership, Opening, Poseidon, RATE};
use crate::crypto::stark::field::Fp;
use alloc::vec::Vec;

pub struct NoteParts {
    pub region: MultiMembership,
    pub trace: Vec<Fp>,
    pub span_op: usize,
    pub cm: [Fp; RATE],
}

/// The owner digest a deposit hands the pool: `compress(spend_pk, blinding)`,
/// the inner of the two compressions `note_parts` chains. The pool's `absorb`
/// takes this opening and computes the outer compression itself from the
/// value it escrowed, so it never sees a key or a blinding and a depositor
/// cannot name a commitment to a note of a different value.
pub fn owner_commit(note: &Note) -> [Fp; RATE] {
    let h = Poseidon::new(POOL_LOG_ROUNDS, [Fp::ZERO; RATE]);
    let q = quads(&note.limbs());
    h.compress(&q[0], &q[1])
}

/// Two compressions, so two depth one openings: the owner digest, then the
/// commitment over the public quad and that digest. The edge chaining them is
/// not implied by the region; see note::edges.
pub fn note_parts(note: &Note) -> NoteParts {
    note_parts_broken(note, false)
}

pub fn note_parts_broken(note: &Note, break_edge: bool) -> NoteParts {
    let h = Poseidon::new(POOL_LOG_ROUNDS, [Fp::ZERO; RATE]);
    let q = quads(&note.limbs());
    let owner = h.compress(&q[0], &q[1]);
    // The compression stays internally honest; only the chain breaks.
    let carried = if break_edge {
        let mut x = owner;
        x[0] = x[0] + Fp::ONE;
        x
    } else {
        owner
    };
    let cm = h.compress(&q[2], &carried);

    let one = |leaf: [Fp; RATE], sib: [Fp; RATE], root: [Fp; RATE]| Opening {
        leaf,
        root,
        siblings: alloc::vec![sib],
        directions: alloc::vec![false],
    };
    let region = MultiMembership::new_witness(
        h,
        POOL_LOG_ROUNDS,
        alloc::vec![one(q[0], q[1], owner), one(q[2], carried, cm)],
    )
    .with_split();
    let trace = region.trace();
    let span_op = region.opened_cells()[1].0;
    NoteParts { region, trace, span_op, cm }
}
