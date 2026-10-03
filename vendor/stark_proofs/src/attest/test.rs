// NONOS Operating System (AGPL-3.0-or-later)
//! A 256-slot tree with a kernel, a capsule and a bootloader among padding;
//! each proven at its slot and refused everywhere a gate must refuse.

use super::circuit::Witness;
use super::native::{hasher, leaf, Statement};
use super::prove::{prove, prove_lanes, verify, Error, POINTS};
use super::{
    shape, DEPTH, DIGEST, KIND, KIND_BOOTLOADER, KIND_CAPSULE, KIND_KERNEL, KIND_PAD, LOG_TRACE,
    ROOT,
};
use crate::crypto::stark::air::{Air, RATE};
use crate::crypto::stark::field::Fp;
use alloc::vec::Vec;

const ENTROPY: [u8; 64] = [7u8; 64];

fn digest(seed: u8) -> [u8; 32] {
    core::array::from_fn(|i| seed.wrapping_mul(31).wrapping_add(i as u8))
}

/// Every level of a 256-slot tree, leaves first.
fn levels(leaves: Vec<[Fp; RATE]>) -> Vec<Vec<[Fp; RATE]>> {
    let h = hasher();
    let mut out = alloc::vec![leaves];
    while out.last().map_or(0, Vec::len) > 1 {
        let up = out
            .last()
            .map(|l| l.chunks(2).map(|p| h.compress(&p[0], &p[1])).collect())
            .unwrap_or_default();
        out.push(up);
    }
    out
}

struct Tree {
    levels: Vec<Vec<[Fp; RATE]>>,
}

impl Tree {
    /// Slot 3 a kernel, 77 a capsule, 200 a bootloader, the rest padding.
    fn new() -> Tree {
        let leaves = (0..1usize << DEPTH)
            .map(|i| match i {
                3 => leaf(KIND_KERNEL, &digest(3)),
                77 => leaf(KIND_CAPSULE, &digest(77)),
                200 => leaf(KIND_BOOTLOADER, &digest(200)),
                _ => leaf(KIND_PAD, &digest(i as u8)),
            })
            .collect();
        Tree {
            levels: levels(leaves),
        }
    }
    fn root(&self) -> [Fp; RATE] {
        self.levels[DEPTH][0]
    }
    fn path(&self, index: usize) -> Witness {
        let (mut siblings, mut right, mut i) = (Vec::new(), Vec::new(), index);
        for level in &self.levels[..DEPTH] {
            siblings.push(level[i ^ 1]);
            right.push(i & 1 == 1);
            i >>= 1;
        }
        Witness { siblings, right }
    }
}

fn statement(t: &Tree, slot: u8, kind: u64) -> Statement {
    Statement::new(t.root(), digest(slot), kind).expect("a provable kind")
}

#[test]
fn the_circuit_is_the_shipped_length() {
    let t = Tree::new();
    let air = shape(&statement(&t, 3, KIND_KERNEL).words()).expect("the shape");
    assert_eq!(Air::log_trace_len(&air), LOG_TRACE);
}

#[test]
fn every_kind_proves_at_its_slot_and_verifies() {
    let t = Tree::new();
    for (slot, kind) in [
        (3u8, KIND_KERNEL),
        (77, KIND_CAPSULE),
        (200, KIND_BOOTLOADER),
    ] {
        let st = statement(&t, slot, kind);
        let w = t.path(slot as usize);
        assert!(st.holds(&w.siblings, &w.right));
        let proof = prove(&st, &w, &ENTROPY, POINTS[0]).expect("the honest proof");
        assert_eq!(verify(&st, &proof), Ok(()), "kind {kind}");
    }
}

#[test]
fn the_same_entropy_gives_the_same_bytes() {
    let t = Tree::new();
    let st = statement(&t, 77, KIND_CAPSULE);
    let a = prove(&st, &t.path(77), &ENTROPY, POINTS[0]).expect("first");
    let b = prove(&st, &t.path(77), &ENTROPY, POINTS[0]).expect("second");
    assert_eq!(a, b);
}

/// A proof of one statement verifies for no other: each word moved alone.
#[test]
fn a_proof_does_not_verify_under_another_statement() {
    let t = Tree::new();
    let st = statement(&t, 77, KIND_CAPSULE);
    let proof = prove(&st, &t.path(77), &ENTROPY, POINTS[0]).expect("the honest proof");

    let mut other = st;
    other.kind = KIND_KERNEL;
    assert!(
        verify(&other, &proof).is_err(),
        "the capsule's proof passed as a kernel's"
    );
    other.kind = KIND_BOOTLOADER;
    assert!(
        verify(&other, &proof).is_err(),
        "the capsule's proof passed as a bootloader's"
    );

    for byte in [0, 9, 31] {
        let mut other = st;
        other.digest[byte] ^= 1;
        assert!(
            verify(&other, &proof).is_err(),
            "the proof passed for another context"
        );
    }
    for lane in 0..RATE {
        let mut other = st;
        other.root[lane] = other.root[lane] + Fp::ONE;
        assert!(
            verify(&other, &proof).is_err(),
            "the proof passed under another root"
        );
    }
}

/// The witness check refuses what the circuit would refuse anyway, with a
/// reason: a capsule's slot named as a kernel, a slot that is not the
/// statement's, padding, and an unaccepted point.
#[test]
fn false_statements_are_refused_before_proving() {
    let t = Tree::new();
    let as_kernel = Statement {
        kind: KIND_KERNEL,
        ..statement(&t, 77, KIND_CAPSULE)
    };
    assert_eq!(
        prove(&as_kernel, &t.path(77), &ENTROPY, POINTS[0]),
        Err(Error::Witness)
    );
    let st = statement(&t, 77, KIND_CAPSULE);
    assert_eq!(
        prove(&st, &t.path(78), &ENTROPY, POINTS[0]),
        Err(Error::Witness)
    );
    assert!(Statement::new(t.root(), digest(5), KIND_PAD).is_none());
    let pad = Statement {
        kind: KIND_PAD,
        ..statement(&t, 5, KIND_CAPSULE)
    };
    assert_eq!(
        prove(&pad, &t.path(5), &ENTROPY, POINTS[0]),
        Err(Error::Shape)
    );
    let weak = super::Point {
        queries: 19,
        grind_bits: 28,
    };
    assert_eq!(prove(&st, &t.path(77), &ENTROPY, weak), Err(Error::Shape));
}

/// A forger who walks the capsule's real leaf while the statement says
/// "kernel": the leaf's lane 5 holds 1, the public word 0, and the wire
/// between them is what refuses. Likewise a digest word written apart from
/// the statement's. Nothing that comes out verifies.
#[test]
fn the_wires_refuse_a_leaf_other_than_the_statements() {
    let t = Tree::new();
    let real = statement(&t, 77, KIND_CAPSULE);
    let words = real.words();
    let lanes = [
        words[DIGEST],
        words[DIGEST + 1],
        words[DIGEST + 2],
        words[DIGEST + 3],
        words[KIND],
    ];

    let claimed = Statement {
        kind: KIND_KERNEL,
        ..real
    };
    match prove_lanes(&claimed, &t.path(77), &ENTROPY, POINTS[0], Some(lanes)) {
        Err(Error::NotVerified(_)) | Err(Error::Prover) | Err(Error::Rank(_)) => {}
        other => panic!("a kernel claim over a capsule's leaf was not refused: {other:?}"),
    }

    let mut other_digest = real;
    other_digest.digest[0] ^= 1;
    match prove_lanes(&other_digest, &t.path(77), &ENTROPY, POINTS[0], Some(lanes)) {
        Err(Error::NotVerified(_)) | Err(Error::Prover) | Err(Error::Rank(_)) => {}
        other => panic!("a digest other than the statement's was not refused: {other:?}"),
    }
    let _ = ROOT;
}

/// The numbers a verifier reading the program image pins beside it
/// (`nox_verify::statements::ATTEST`). A change to the circuit that moves one
/// fails here first.
#[test]
fn the_shape_is_the_one_the_gate_verifier_pins() {
    use crate::crypto::stark::air::{AirExt, Permuted};
    let t = Tree::new();
    let air = shape(&statement(&t, 3, KIND_KERNEL).words()).expect("the shape");
    let facts = (
        Air::trace_width(&air),
        air.region_width(),
        Air::constraint_degree(&air),
        air.mask_pair(),
        air.challenge_lanes(),
        Air::periodic_columns(&air).len(),
    );
    std::println!("attest shape (width, region, degree, mask, lanes, periodic) = {facts:?}");
    assert_eq!(
        facts,
        (
            ATTEST_WIDTH,
            ATTEST_REGION,
            ATTEST_DEGREE,
            ATTEST_MASK,
            2,
            ATTEST_PERIODIC
        )
    );
}

const ATTEST_WIDTH: usize = 33;
const ATTEST_REGION: usize = 29;
const ATTEST_DEGREE: usize = 8;
const ATTEST_MASK: Option<(usize, usize)> = Some((31, 32));
const ATTEST_PERIODIC: usize = 22;

/// The coverage audit of every witness cell, the same check the transfer
/// circuit is held to (`cell_audit_test::audit_free_cells`): each cell of a
/// satisfying witness changed alone, and every change no window and no
/// boundary sees named by a rule. The counts are pinned, so a cell that
/// becomes free fails here until someone gives it a reason.
#[test]
fn every_free_cell_of_the_attestation_has_a_rule() {
    let t = Tree::new();
    let st = statement(&t, 77, KIND_CAPSULE);
    let b = super::circuit::build(&st.words(), Some(&t.path(77)), None).expect("the circuit");
    let witness = b.wired.trace(&b.traces);
    assert!(
        crate::witness_satisfies::satisfies(&b.wired, &witness),
        "the honest witness does not satisfy"
    );
    let audit = crate::cell_audit_test::audit_free_cells(&b.wired, &witness);
    std::println!(
        "attestation cells {}, read {}, free {}: a {}, b {}",
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
 * 2^14 rows of 33 columns. Free by layout (a): 243,536 padding-row cells,
 * 229,824 past a region's width, 17,056 in the mask columns. Free by name
 * (b): 8,197 publics rows past the nine words (the padding region's and the
 * statement's), 23 on regions' last rows. The statement's own cells, the leaf
 * lanes of row 0 and the root at the checkpoint, are all read.
 */
const AUDIT_CELLS: usize = 540_672;
const AUDIT_READ: usize = 42_036;
const AUDIT_A: usize = 490_416;
const AUDIT_B: usize = 8_220;

/// The Lean model's constants and wire table are the circuit's: read out of
/// `lean/Shield/Attest.lean`, compared with what `circuit` builds. A change on
/// either side without the other fails here.
#[test]
fn the_lean_model_is_the_circuit() {
    use super::circuit::{pins, wires, CHECKPOINT_ROW};
    use super::{LEAF_DOMAIN, PAD_LOG, WORDS};
    const LEAN: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../lean/Shield/Attest.lean"
    ));
    let def = |name: &str| -> u64 {
        let key = std::format!("def {name} : Nat := ");
        let at = LEAN
            .find(&key)
            .unwrap_or_else(|| panic!("{name} is not defined in Attest.lean"));
        LEAN[at + key.len()..]
            .split_whitespace()
            .next()
            .and_then(|v| v.parse().ok())
            .expect("a number")
    };
    assert_eq!(def("depth"), DEPTH as u64);
    assert_eq!(def("rounds"), 1 << super::LOG_ROUNDS);
    assert_eq!(def("words"), WORDS as u64);
    assert_eq!(def("root"), ROOT as u64);
    assert_eq!(def("digest"), DIGEST as u64);
    assert_eq!(def("kind"), KIND as u64);
    assert_eq!(def("leafDomain"), LEAF_DOMAIN);
    assert_eq!(def("padKind"), KIND_PAD);
    assert_eq!(def("logTrace"), LOG_TRACE as u64);
    assert_eq!(def("publicsRows"), 16);
    assert_eq!(def("padRows"), 1 << PAD_LOG);

    // The wire table, as Lean writes it: `(word, row, lane)` triples.
    let at = LEAN.find("def wires").expect("the wire table");
    let body = &LEAN[at..at + LEAN[at..].find("]\n").expect("its end")];
    let nums: Vec<usize> = body
        .split(|c: char| !c.is_ascii_digit())
        .filter(|t| !t.is_empty())
        .map(|t| t.parse().expect("a number"))
        .collect();
    let lean_wires: Vec<(usize, usize, usize)> =
        nums.chunks_exact(3).map(|c| (c[0], c[1], c[2])).collect();
    assert_eq!(lean_wires, wires().to_vec());
    assert!(lean_wires.iter().take(4).all(|w| w.1 == CHECKPOINT_ROW));

    let pin_lanes: Vec<usize> = pins().iter().map(|p| p.0).collect();
    assert_eq!(pin_lanes, [0, 6, 7]);
    assert_eq!(pins()[0].1, LEAF_DOMAIN);

    // The chain is the rows Lean counts, and the trace the length it proves.
    let t = Tree::new();
    let air = shape(&statement(&t, 3, KIND_KERNEL).words()).expect("the shape");
    let chain_rows = match &air.regions()[0] {
        crate::crypto::stark::air::ShieldRegion::Membership(m) => Air::rows(m),
        _ => panic!("the first region is the slot's chain"),
    };
    assert_eq!(
        chain_rows as u64,
        (2 + DEPTH as u64) * (1 << super::LOG_ROUNDS)
    );
    assert_eq!(Air::log_trace_len(&air), LOG_TRACE);
}
