// NONOS Operating System (AGPL-3.0-or-later)

use super::derive::derive;
use super::domain::tag;
use crate::crypto::stark::air::{MultiMembership, Opening, Poseidon, RATE};
use crate::crypto::stark::field::Fp;
use crate::shield::note::POOL_LOG_ROUNDS;
use alloc::vec::Vec;

/// Which tie to cut, so a reject fires through one binding and nothing else.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Break {
    None,
    /// A different secret behind the nullifier key: the two derivations no
    /// longer share one sk.
    ForeignKey,
    /// Absorb a commitment other than the one membership proved.
    ForeignNote,
    /// Spend a note whose committed key this secret did not derive.
    NotOwner,
    /// Three honest compressions that are not chained into a commitment.
    NoteEdge,
    /// Prove association membership of a note other than the one spent.
    Unlisted,
    /// Retire the note under a leaf index other than the one the pool authenticated.
    /// The note is genuinely owned and genuinely a member; only the position the
    /// nullifier hashes moves. Two of these over one note are two nullifiers, and
    /// two nullifiers over one note is that note spent twice.
    ForeignIndex,
    /// Declare an input dead while it carries value, which is the only thing a
    /// dead bit is worth forging: a dead input skips its membership proof, so a
    /// prover would use it to spend a note that is not in the pool. The gate's
    /// second constraint refuses it, because a dead input must be worth zero
    /// and an input worth zero moves nothing.
    DeadCarrier,
    /// Derive the nullifier key under a word other than the domain constant.
    /// The note is owned, the membership holds, the position is the one the
    /// pool authenticated, and the four compressions chain. Only the second
    /// one's absorbed word moves, and that word is a witness cell.
    ForeignDomain,
    /// Hash a dummy's nullifier under the word a real note hashes. The dead
    /// lane is the one thing keeping a burned dummy out of the space a note's
    /// nullifier occupies, and the pool burns both without being able to tell
    /// them apart.
    LiveDeadLane,
    /// The same double spend through bit zero alone, the leaf's own left or right.
    /// `ForeignIndex` adds one, which carries past bit zero for an odd position and
    /// is then caught by a higher bit's binding. This flips bit zero with xor, so
    /// every higher bit is untouched and still agrees with the membership, and the
    /// recovered scalar and the nullifier both move to the sibling position. Only
    /// bit zero differs from what the pool authenticated. If nothing pins it, the
    /// note retires under two positions.
    ForeignIndex0,
}

pub struct NullifierParts {
    pub region: MultiMembership,
    pub trace: Vec<Fp>,
    pub span_op: usize,
    pub nf: [Fp; RATE],
    pub spend_pk: [Fp; RATE],
}

/*
 * The words the key hierarchy absorbs that are constants rather than choices.
 *
 * Each compression absorbs into the high half of its first row, and in the
 * production form that half is a witness cell. Three of the four are held:
 * the spend key's result must equal the word the note committed to, the third
 * absorbs the commitment membership authenticated, and the fourth's low lane is
 * the position the path recovered. What was left is every lane of the two
 * domain words and the three high lanes of the position, and a prover who moves
 * any of them derives a different key down a chain that closes just as well.
 * That is a second nullifier over one note, which is that note spent twice.
 *
 * Lane one of the position word is the exception and is not pinned here: it
 * says live or dead, and the live gate is the only region that knows which.
 *
 * What holds them is a boundary per distinct value plus one wiring class over
 * the lanes that share zero, rather than a boundary per lane. Same cells, same
 * values, fewer boundaries, and the boundary count is what the wrap is priced
 * in.
 *
 * `shield::test::nullifier_domain`.
 */
fn domain_boundary() -> Vec<(usize, usize, Fp)> {
    let span = 2 * (1usize << POOL_LOG_ROUNDS);
    /*
     * Three pins where this was ten, one per distinct value rather than one per
     * lane. The lanes hold three values between them: the two domain constants,
     * in lane zero of each word, and zero everywhere else. A boundary can only
     * say "this cell is that constant", so the eight zero lanes are one wiring
     * class instead, `key::domain_zero_cells`, anchored to the pin below. A
     * class forces equality and the pin forces the value, and together they say
     * what ten boundaries said over the same cells.
     *
     * Each inner boundary costs the outer ten DEEP terms, and the wrap's region
     * halves at 2047 against an emitted 2523: `shield::test::inner_cost`. This
     * is the cheapest part of that gap and it gives up no soundness surface,
     * because the cells are the same cells held to the same values through one
     * more mechanism rather than one fewer.
     */
    let mut b = Vec::with_capacity(3);
    for (o, d) in [super::domain::SPEND_DOMAIN, super::domain::NULL_DOMAIN]
        .iter()
        .enumerate()
    {
        b.push((RATE, o * span, tag(*d)[0]));
    }
    // The class's anchor, which has to be a cell the class contains: lane one of
    // the spend domain word, at the first compression.
    b.push((RATE + 1, 0, Fp::ZERO));
    b
}

/// The trace cell carrying lane one of the position word, in the region's own
/// coordinates: the live gate binds its own copy here.
pub fn dead_lane_cell(span_op: usize) -> (usize, usize) {
    (3 * span_op, RATE + 1)
}

pub fn nullifier_parts(
    sk: [Fp; RATE],
    cm: [Fp; RATE],
    leaf_index: u64,
    live: bool,
    brk: Break,
) -> NullifierParts {
    let h = Poseidon::new(POOL_LOG_ROUNDS, [Fp::ZERO; RATE]);
    let mut nk_sk = sk;
    if brk == Break::ForeignKey {
        nk_sk[0] = nk_sk[0] + Fp::ONE;
    }
    let mut target = cm;
    if brk == Break::ForeignNote {
        target[0] = target[0] + Fp::ONE;
    }

    let null_word = match brk {
        Break::ForeignDomain => tag(super::domain::NULL_DOMAIN + 1),
        _ => tag(super::domain::NULL_DOMAIN),
    };
    let spend_pk = derive(&h, sk).spend_pk;
    let nk = h.compress(&nk_sk, &null_word);
    let idx = match brk {
        Break::ForeignIndex => leaf_index + 1,
        Break::ForeignIndex0 => leaf_index ^ 1,
        _ => leaf_index,
    };
    let pos = super::domain::position_word(idx, live || brk == Break::LiveDeadLane);
    let t = h.compress(&nk, &target);
    let nf = h.compress(&t, &pos);

    let one = |leaf: [Fp; RATE], sib: [Fp; RATE], root: [Fp; RATE]| Opening {
        leaf,
        root,
        siblings: alloc::vec![sib],
        directions: alloc::vec![false],
    };
    let region = MultiMembership::new_witness_bound(
        h,
        POOL_LOG_ROUNDS,
        alloc::vec![
            one(sk, tag(super::domain::SPEND_DOMAIN), spend_pk),
            one(nk_sk, null_word, nk),
            one(nk, target, t),
            one(t, pos, nf),
        ],
        domain_boundary(),
    )
    .with_split();
    let trace = region.trace();
    let span_op = region.opened_cells()[1].0;
    NullifierParts { region, trace, span_op, nf, spend_pk }
}
