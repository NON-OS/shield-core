// NONOS Operating System (AGPL-3.0-or-later)
//! A week's spend tree holding five of one key's notes among other spends and
//! one of its dummies; claims of one, two and four spends proven, and every
//! false claim refused, first directly and then by the circuit itself.

use super::circuit::{Slot, Witness};
use super::native::{hasher, key_commitment, nullifier, tag, Statement};
use super::prove::{prove, prove_unchecked, verify, Error};
use super::{shape, DEPTH, LOG_TRACE, SLOTS};
use crate::crypto::stark::air::{Air, RATE};
use crate::crypto::stark::field::Fp;
use crate::shield::key::{nullifier as key_nullifier, DEAD_DOMAIN};
use crate::shield::member::PoolTree;
use alloc::vec::Vec;

const ENTROPY: [u8; 64] = [9u8; 64];
const WEEK: u64 = 2_934;
const NK: [u64; RATE] = [0x1111, 0x2222, 0x3333, 0x4444];
const PAYOUT: [u64; RATE] = [11, 12, 13, 14];

fn f4(v: [u64; RATE]) -> [Fp; RATE] {
    v.map(Fp::from_u64)
}

fn nk() -> [Fp; RATE] {
    f4(NK)
}

/// The key's notes: commitment and note-tree position.
fn note(i: u64) -> ([Fp; RATE], u64) {
    (f4([100 + i, 200 + i, 300 + i, 400 + i]), 1_000 + 7 * i)
}

/// What a leaf of the week's tree is.
enum Leaf {
    Other(u64),
    Mine(u64),
    Dummy(u64),
}

/// The week: other spends, five of ours at leaves 1, 3, 4, 6 and 7, a dummy of
/// ours at 8.
const WEEK_LEAVES: [Leaf; 10] = [
    Leaf::Other(0),
    Leaf::Mine(0),
    Leaf::Other(1),
    Leaf::Mine(1),
    Leaf::Mine(2),
    Leaf::Other(2),
    Leaf::Mine(3),
    Leaf::Mine(4),
    Leaf::Dummy(5),
    Leaf::Other(3),
];

struct Week {
    tree: PoolTree,
    /// Leaf index of each of our live notes, by note.
    mine: Vec<(u64, usize)>,
    dummy: (u64, usize),
}

impl Week {
    fn new() -> Week {
        let mut tree = PoolTree::with_depth(hasher(), DEPTH);
        let (mut mine, mut dummy) = (Vec::new(), (0, 0));
        for leaf in &WEEK_LEAVES {
            let at = match *leaf {
                Leaf::Other(i) => tree.insert(f4([9_000 + i, 1, 2, 3])),
                Leaf::Mine(i) => {
                    let (cm, pos) = note(i);
                    let at = tree.insert(nullifier(nk(), cm, pos));
                    mine.push((i, at));
                    at
                }
                Leaf::Dummy(i) => {
                    let (cm, pos) = note(i);
                    let at = tree.insert(key_nullifier(&hasher(), nk(), cm, pos, false));
                    dummy = (i, at);
                    at
                }
            };
            let _ = at;
        }
        Week { tree, mine, dummy }
    }

    fn slot(&self, i: u64, at: usize) -> Slot {
        let (cm, note_position) = note(i);
        let (siblings, right) = self.tree.path(at);
        Slot {
            cm,
            note_position,
            siblings,
            right,
        }
    }

    /// A witness over our live notes `which` (indices into `mine`), in that order.
    fn witness(&self, which: &[usize]) -> Witness {
        let mut slots: [Option<Slot>; SLOTS] = Default::default();
        for (j, &m) in which.iter().enumerate() {
            let (i, at) = self.mine[m];
            slots[j] = Some(self.slot(i, at));
        }
        Witness { nk: nk(), slots }
    }

    fn statement(&self, count: u64) -> Statement {
        Statement::new(
            self.tree.root(),
            WEEK,
            count,
            tag(nk(), WEEK),
            f4(PAYOUT),
            key_commitment(nk()),
        )
        .expect("a count of 1 to 4")
    }
}

fn refused_by_circuit(r: Result<Vec<u8>, Error>, what: &str) {
    match r {
        Err(Error::NotVerified(_)) | Err(Error::Prover) | Err(Error::Rank(_)) => {}
        other => panic!(
            "{what} was not refused by the circuit: {:?}",
            other.map(|b| b.len())
        ),
    }
}

#[test]
fn the_nullifier_is_the_pools() {
    let (cm, pos) = note(0);
    assert_eq!(
        nullifier(nk(), cm, pos),
        key_nullifier(&hasher(), nk(), cm, pos, true)
    );
    assert_ne!(
        nullifier(nk(), cm, pos),
        key_nullifier(&hasher(), nk(), cm, pos, false)
    );
}

#[test]
fn the_circuit_is_the_shipped_length() {
    let air = shape(&Week::new().statement(1).words()).expect("the shape");
    assert_eq!(Air::log_trace_len(&air), LOG_TRACE);
}

#[test]
fn one_two_and_four_spends_prove_and_verify() {
    let wk = Week::new();
    for which in [&[2usize][..], &[0, 3], &[0, 1, 3, 4]] {
        let st = wk.statement(which.len() as u64);
        let bytes = prove(&st, &wk.witness(which), &ENTROPY).expect("an honest claim proves");
        verify(&st, &bytes).expect("and verifies");
        std::println!("activity k={} proof {} bytes", which.len(), bytes.len());
    }
}

#[test]
fn a_proof_does_not_verify_under_another_statement() {
    let wk = Week::new();
    let st = wk.statement(2);
    let bytes = prove(&st, &wk.witness(&[1, 2]), &ENTROPY).expect("an honest claim proves");
    let mut others = Vec::new();
    others.push(Statement { count: 3, ..st });
    others.push(Statement {
        week: WEEK + 1,
        ..st
    });
    let mut t = st;
    t.tag[0] = t.tag[0] + Fp::ONE;
    others.push(t);
    let mut t = st;
    t.payout[3] = t.payout[3] + Fp::ONE;
    others.push(t);
    let mut t = st;
    t.lambda[1] = t.lambda[1] + Fp::ONE;
    others.push(t);
    let mut t = st;
    t.key[2] = t.key[2] + Fp::ONE;
    others.push(t);
    for o in others {
        assert!(verify(&o, &bytes).is_err(), "verified under {o:?}");
    }
}

#[test]
fn false_claims_are_refused_before_proving() {
    let wk = Week::new();
    let st2 = wk.statement(2);
    let w = wk.witness(&[1, 1]);
    assert!(
        matches!(prove(&st2, &w, &ENTROPY), Err(Error::Witness(_))),
        "a repeated spend"
    );
    let w = wk.witness(&[3, 1]);
    assert!(
        matches!(prove(&st2, &w, &ENTROPY), Err(Error::Witness(_))),
        "falling positions"
    );
    let w = wk.witness(&[1, 2, 3]);
    assert!(
        matches!(prove(&st2, &w, &ENTROPY), Err(Error::Witness(_))),
        "three spends claimed as two"
    );

    let mut w = wk.witness(&[1, 2]);
    w.slots[1] = Some(wk.slot(wk.dummy.0, wk.dummy.1));
    assert!(
        matches!(prove(&st2, &w, &ENTROPY), Err(Error::Witness(_))),
        "a dummy counted"
    );

    let mut w = wk.witness(&[1]);
    w.slots[2] = w.slots[0].take();
    w.slots[0] = Some(wk.slot(wk.mine[0].0, wk.mine[0].1));
    w.slots[1] = None;
    assert_eq!(
        prove(&st2, &w, &ENTROPY),
        Err(Error::Shape),
        "a live slot after a dead one"
    );

    let other_week = Statement {
        tag: tag(nk(), WEEK + 1),
        ..st2
    };
    assert!(matches!(
        prove(&other_week, &wk.witness(&[1, 2]), &ENTROPY),
        Err(Error::Witness(_))
    ));
    let other_k = Statement {
        key: key_commitment(f4([1, 2, 3, 4])),
        ..st2
    };
    assert!(
        matches!(
            prove(&other_k, &wk.witness(&[1, 2]), &ENTROPY),
            Err(Error::Witness(_))
        ),
        "another key's K"
    );
    let k = key_commitment(nk());
    assert!(Statement::new(wk.tree.root(), WEEK, 0, tag(nk(), WEEK), f4(PAYOUT), k).is_none());
    assert!(Statement::new(wk.tree.root(), WEEK, 5, tag(nk(), WEEK), f4(PAYOUT), k).is_none());
}

/// The same false claims with the direct check skipped: the circuit alone
/// refuses each.
#[test]
fn the_circuit_refuses_what_the_check_refuses() {
    let wk = Week::new();
    let honest = [Fp::ZERO; SLOTS];
    let st2 = wk.statement(2);
    refused_by_circuit(
        prove_unchecked(&st2, &wk.witness(&[1, 1]), &ENTROPY, honest),
        "a repeated spend",
    );
    refused_by_circuit(
        prove_unchecked(&st2, &wk.witness(&[3, 1]), &ENTROPY, honest),
        "falling positions",
    );
    refused_by_circuit(
        prove_unchecked(&st2, &wk.witness(&[1, 2, 3]), &ENTROPY, honest),
        "three spends claimed as two",
    );
    refused_by_circuit(
        prove_unchecked(&wk.statement(3), &wk.witness(&[1, 2]), &ENTROPY, honest),
        "two claimed as three",
    );

    // A dummy's nullifier is in the tree; counting it needs the dead lane.
    let mut w = wk.witness(&[1, 2]);
    w.slots[1] = Some(wk.slot(wk.dummy.0, wk.dummy.1));
    let mut lanes = honest;
    lanes[1] = Fp::from_u64(DEAD_DOMAIN);
    refused_by_circuit(
        prove_unchecked(&st2, &w, &ENTROPY, lanes),
        "a dummy counted through its dead lane",
    );
    refused_by_circuit(
        prove_unchecked(&st2, &w, &ENTROPY, honest),
        "a dummy counted as live",
    );

    let mut w = wk.witness(&[1]);
    w.slots[2] = Some(wk.slot(wk.mine[2].0, wk.mine[2].1));
    refused_by_circuit(
        prove_unchecked(&st2, &w, &ENTROPY, honest),
        "a live slot after a dead one",
    );

    let other_week = Statement {
        tag: tag(nk(), WEEK + 1),
        ..st2
    };
    refused_by_circuit(
        prove_unchecked(&other_week, &wk.witness(&[1, 2]), &ENTROPY, honest),
        "another week's tag",
    );
    let mut other_key = wk.witness(&[1, 2]);
    other_key.nk[0] = other_key.nk[0] + Fp::ONE;
    refused_by_circuit(
        prove_unchecked(&st2, &other_key, &ENTROPY, honest),
        "another key",
    );
    /*
     * Another key's K with this key's spends and tag: the sale S10.1 closes, a
     * proof made by one key and registered under another's commitment.
     */
    let other_k = Statement {
        key: key_commitment(f4([1, 2, 3, 4])),
        ..st2
    };
    refused_by_circuit(
        prove_unchecked(&other_k, &wk.witness(&[1, 2]), &ENTROPY, honest),
        "another key's K",
    );
    let off_tree = Statement {
        lambda: f4([1, 2, 3, 4]),
        ..st2
    };
    refused_by_circuit(
        prove_unchecked(&off_tree, &wk.witness(&[1, 2]), &ENTROPY, honest),
        "another week's root",
    );
}

#[test]
fn the_same_entropy_gives_the_same_bytes() {
    let wk = Week::new();
    let st = wk.statement(1);
    let a = prove(&st, &wk.witness(&[0]), &ENTROPY).expect("proves");
    let b = prove(&st, &wk.witness(&[0]), &ENTROPY).expect("proves");
    assert_eq!(a, b);
}

/// The coverage audit of every witness cell (`cell_audit_test::audit_free_cells`),
/// on a claim with two live slots and two dead, so both kinds of slot are
/// audited. The counts are pinned: a cell that becomes free fails here until
/// someone gives it a reason.
#[test]
fn every_free_cell_of_the_activity_claim_has_a_rule() {
    let wk = Week::new();
    let st = wk.statement(2);
    let b = super::circuit::build(&st.words(), Some(&wk.witness(&[1, 3]))).expect("the circuit");
    let witness = b.wired.trace(&b.traces);
    assert!(
        crate::witness_satisfies::satisfies(&b.wired, &witness),
        "the honest witness does not satisfy"
    );
    let audit = crate::cell_audit_test::audit_free_cells(&b.wired, &witness);
    std::println!(
        "activity cells {}, read {}, free {}: a {}, b {}",
        audit.cells,
        audit.cells - audit.free,
        audit.free,
        audit.class('a'),
        audit.class('b')
    );
    for (why, count) in &audit.by_rule {
        std::println!("  {why}: {count}");
    }
    assert!(
        audit.unexplained.is_empty(),
        "free cells no rule explains: {:?}",
        &audit.unexplained[..audit.unexplained.len().min(20)]
    );
    assert_eq!(
        (
            audit.cells,
            audit.cells - audit.free,
            audit.class('a'),
            audit.class('b')
        ),
        (AUDIT_CELLS, AUDIT_READ, AUDIT_A, AUDIT_B)
    );
}

/*
 * 2^13 rows of 46 columns. Free by layout (a): 45,050 padding-row cells,
 * 140,958 past a region's width, 13,734 in the mask columns. Free by name
 * (b): 4,108 publics rows past the words, 166 on regions' last rows, 60 index
 * bits past the sixteenth. Dead slots' cells are all read: their chains are
 * constrained like live ones and their walked roots are wired to the count.
 */
const AUDIT_CELLS: usize = 376_832;
const AUDIT_READ: usize = 172_756;
const AUDIT_A: usize = 199_742;
const AUDIT_B: usize = 4_334;

/// The Lean model's constants are the circuit's: read out of
/// `lean/Shield/Activity.lean` and compared with what `circuit` builds.
#[test]
fn the_lean_model_is_the_circuit() {
    use super::circuit::{pins, CHECKPOINT_ROW, COMPRESSIONS, POSITION_ROW};
    use super::{ACTIVITY_DOMAIN, COUNT, LAMBDA, LOG_ROUNDS, PAYOUT, TAG, WEEK, WORDS};
    use crate::crypto::stark::air::{ActivityCount, ShieldRegion, WIDTH};
    const LEAN: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../lean/Shield/Activity.lean"
    ));
    let def = |name: &str| -> u64 {
        let key = std::format!("def {name} : Nat := ");
        let at = LEAN
            .find(&key)
            .unwrap_or_else(|| panic!("{name} is not defined in Activity.lean"));
        LEAN[at + key.len()..]
            .split_whitespace()
            .next()
            .and_then(|v| v.parse().ok())
            .expect("a number")
    };
    let list = |name: &str| -> Vec<u64> {
        let at = LEAN
            .find(&std::format!("def {name} "))
            .unwrap_or_else(|| panic!("{name} is not in Activity.lean"));
        let body = &LEAN[at + LEAN[at..].find(":=").expect("its body")..];
        let body = &body[..body.find("]\n").expect("its end")];
        body.split(|c: char| !c.is_ascii_digit())
            .filter(|t| !t.is_empty())
            .map(|t| t.parse().expect("a number"))
            .collect()
    };
    assert_eq!(def("p"), (Fp::ZERO - Fp::ONE).to_u64() as u64 + 1);
    assert_eq!(def("slots"), SLOTS as u64);
    assert_eq!(def("depth"), DEPTH as u64);
    assert_eq!(def("rounds"), 1 << LOG_ROUNDS);
    assert_eq!(def("words"), WORDS as u64);
    assert_eq!(def("lambda"), LAMBDA as u64);
    assert_eq!(def("week"), WEEK as u64);
    assert_eq!(def("count"), COUNT as u64);
    assert_eq!(def("tag"), TAG as u64);
    assert_eq!(def("payout"), PAYOUT as u64);
    assert_eq!(def("key"), super::KEY as u64);
    assert_eq!(def("keyDomain"), super::KEY_DOMAIN);
    assert_eq!(def("activityDomain"), ACTIVITY_DOMAIN);
    assert_eq!(def("logTrace"), LOG_TRACE as u64);
    assert_eq!(def("dirCol"), WIDTH as u64);
    assert_eq!(def("colLive"), ActivityCount::LIVE as u64);
    assert_eq!(def("colPos"), ActivityCount::POS as u64);
    assert_eq!(def("colGap"), ActivityCount::GAP as u64);
    assert_eq!(def("colK"), ActivityCount::K as u64);
    assert_eq!(def("colWalked"), ActivityCount::WALKED as u64);
    assert_eq!(def("colRoot"), ActivityCount::ROOT as u64);
    assert_eq!(def("countWidth"), ActivityCount::WIDTH as u64);
    assert_eq!((COMPRESSIONS, POSITION_ROW, CHECKPOINT_ROW), (18, 32, 576));

    // The pins, as Lean writes them `(row, column)`, all zero.
    let lean_pins: Vec<(usize, usize)> = list("pins")
        .chunks_exact(2)
        .map(|c| (c[0] as usize, c[1] as usize))
        .collect();
    let pins: Vec<(usize, usize)> = pins()
        .iter()
        .map(|&(col, row, v)| {
            assert_eq!(v, Fp::ZERO);
            (row, col)
        })
        .collect();
    assert_eq!(lean_pins, pins);

    // The regions' rows, in stack order, and the trace length.
    let wk = Week::new();
    let air = shape(&wk.statement(1).words()).expect("the shape");
    let rows: Vec<u64> = air
        .regions()
        .iter()
        .map(|g| match g {
            ShieldRegion::Membership(m) => Air::rows(m),
            ShieldRegion::Index(i) => Air::rows(i),
            ShieldRegion::Count(c) => Air::rows(c),
            ShieldRegion::Range(r) => Air::rows(r),
            ShieldRegion::Publics(p) => Air::rows(p),
            _ => panic!("a region the activity circuit does not build"),
        } as u64)
        .collect();
    assert_eq!(rows, list("regionRows"));
    assert_eq!(Air::log_trace_len(&air), LOG_TRACE);
}

/// The numbers a verifier reading the program image pins beside it
/// (`nox_verify::statements::ACTIVITY`). A change to the circuit that moves
/// one fails here first.
#[test]
fn the_shape_is_the_one_the_verifier_pins() {
    use crate::crypto::stark::air::{AirExt, Permuted};
    let air = shape(&Week::new().statement(1).words()).expect("the shape");
    let facts = (
        Air::trace_width(&air),
        air.region_width(),
        Air::constraint_degree(&air),
        air.mask_pair(),
        air.challenge_lanes(),
        Air::periodic_columns(&air).len(),
    );
    std::println!("activity shape (width, region, degree, mask, lanes, periodic) = {facts:?}");
    assert_eq!(facts, ACTIVITY_SHAPE);
}

const ACTIVITY_SHAPE: (usize, usize, usize, Option<(usize, usize)>, usize, usize) =
    (46, 32, 11, Some((44, 45)), 2, 92);
