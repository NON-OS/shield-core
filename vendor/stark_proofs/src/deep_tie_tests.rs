// NONOS Operating System (AGPL-3.0-or-later)
// The consistency check runs at FRI's positions and reads FRI's codeword.
//
// Format 4 tied the DEEP value to FRI's first root but drew the consistency
// positions from the STARK transcript before any nonce, so re-blinding the
// proof re-rolled them for free and the check was not ground. Format 5 draws
// one set of positions, in FRI's transcript after its nonce, seeded by the
// STARK transcript, and reads the DEEP value from FRI's own layer-zero
// opening. These build the forgeries each half of that rules out and check
// the refusal names the check that caught it.

use crate::crypto::stark::air::replay_pre::replay_comp_z_pre;
use crate::crypto::stark::air::{
    blinding_poly, stark_prove_ext_rounds, stark_verify_ext_rounds_why, Air, StarkProofExtRounds,
};
use crate::crypto::stark::field::{Fp, Fp2};
use crate::crypto::stark::fri_ext::fri_positions_ext;
use crate::crypto::stark::merkle::MerkleTree;
use crate::recursion_assembly::inner;
use crate::wired_rounds_tests::{air, region, BLOWUP, GRIND, QUERIES};

fn prove(tag: u64) -> (StarkProofExtRounds, MerkleTree) {
    let h = inner::hasher();
    let width = Air::trace_width(&air());
    let seed = [
        Fp::from_u64(tag),
        Fp::from_u64(2),
        Fp::from_u64(3),
        Fp::from_u64(4),
    ];
    let blinds: Vec<Vec<Fp>> = (0..width)
        .map(|c| blinding_poly(&h, &seed, c, QUERIES + 2))
        .collect();
    let mut t = air().trace(&[region().trace()]);
    let (rounds, p_tree, _) =
        stark_prove_ext_rounds(air(), &mut t, QUERIES, GRIND, BLOWUP, &[], None, &blinds)
            .expect("the prover produces a proof");
    (rounds, p_tree)
}

fn why(rounds: &StarkProofExtRounds, root: &MerkleTree) -> Result<(), &'static str> {
    stark_verify_ext_rounds_why(air(), rounds, QUERIES, GRIND, BLOWUP, &root.root(), &[])
}

fn one() -> Fp2 {
    Fp2 {
        c0: Fp::ONE,
        c1: Fp::ZERO,
    }
}

#[test]
fn an_honest_proof_verifies() {
    let (r, t) = prove(11);
    assert_eq!(why(&r, &t), Ok(()));
}

/// The positions FRI draws under the seed the STARK transcript hands it: one
/// set, drawn once, and moved by the seed.
#[test]
fn the_consistency_positions_are_fris() {
    let (r, _) = prove(11);
    let mut a = air();
    let replay =
        replay_comp_z_pre(&mut a, &r.pre, Some(&r.perm_root), BLOWUP, &[]).expect("replays");
    // layer zero sits two levels under the domain at radix four
    let log_n = r.pre.proof.fri.queries[0].layers[0].path.len() as u32 + 2;
    let positions = fri_positions_ext(&r.pre.proof.fri, log_n, Some(&replay.seed));
    assert_eq!(positions.len(), QUERIES);
    let unseeded = fri_positions_ext(&r.pre.proof.fri, log_n, None);
    assert_ne!(positions, unseeded, "the seed must move the positions");
}

/*
 * The forgery format 4 had to rule out, and one format 5 adds a reason to:
 * another proof's FRI. Its roots are another word's and its positions were
 * drawn under another seed, so under this proof's seed its chain does not
 * check.
 */
#[test]
fn the_fri_of_another_proof_is_refused() {
    let (mut a, t) = prove(11);
    let (b, _) = prove(22);
    assert_ne!(
        a.pre.proof.fri.roots, b.pre.proof.fri.roots,
        "the two words are one word"
    );
    a.pre.proof.fri = b.pre.proof.fri;
    assert_eq!(why(&a, &t), Err("the FRI refused"));
}

/// The DEEP value is FRI's layer-zero value: bending it is bending FRI.
#[test]
fn the_deep_value_is_fris_to_bend() {
    for slot in 0..4 {
        let (mut a, t) = prove(11);
        let v = &mut a.pre.proof.fri.queries[3].layers[0].v[slot];
        *v = *v + one();
        assert_eq!(why(&a, &t), Err("the FRI refused"), "slot {slot}");
    }
}

/// Openings made at another proof's positions are openings at the wrong
/// places: the paths refuse before any arithmetic runs.
#[test]
fn openings_at_other_positions_are_refused() {
    let (mut a, t) = prove(11);
    let (b, _) = prove(22);
    a.pre.proof.queries = b.pre.proof.queries;
    a.pre.openings = b.pre.openings;
    a.perm_paths = b.perm_paths;
    assert_eq!(why(&a, &t), Err("a Merkle path refused"));
}

#[test]
fn a_bent_trace_value_is_refused() {
    let (mut a, t) = prove(11);
    a.pre.proof.queries[2].trace[0] = a.pre.proof.queries[2].trace[0] + Fp::ONE;
    assert_eq!(why(&a, &t), Err("a Merkle path refused"));
}

/// The seed carries the statement: the same proof under other publics draws
/// other challenges and other positions, and is refused.
#[test]
fn another_statement_is_refused() {
    let (r, t) = prove(11);
    let got = stark_verify_ext_rounds_why(air(), &r, QUERIES, GRIND, BLOWUP, &t.root(), &[Fp::ONE]);
    assert!(got.is_err());
}

#[test]
fn the_codec_carries_no_deep_opening() {
    use crate::crypto::stark::air::deserialize_proof_ext;
    use crate::proof_wire::serialize_pre;
    let (a, _) = prove(11);
    let back = deserialize_proof_ext(&serialize_pre(&a.pre)).expect("the encoding reads back");
    assert_eq!(back.queries.len(), a.pre.proof.queries.len());
    for (x, y) in a.pre.proof.queries.iter().zip(back.queries.iter()) {
        assert_eq!(x.trace, y.trace);
        assert_eq!(x.comp, y.comp);
    }
    assert_eq!(back.fri.roots, a.pre.proof.fri.roots);
}
