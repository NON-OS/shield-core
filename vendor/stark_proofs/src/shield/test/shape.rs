// NONOS Operating System (AGPL-3.0-or-later)

//! The circuit rebuilt from the public words is the circuit the wallet proved.
//!
//! `join_split_shape` builds the join-split over a witness nobody owns and
//! the wallet's intent. If any part of the AIR a relayer holds came from the
//! secrets, the two circuits would differ somewhere a verifier reads: a
//! boundary, a periodic column, a permutation, a transition. Every one of
//! those is compared here against the circuit the real witness built.

use crate::crypto::stark::air::{Air, AirExt, RATE};
use crate::crypto::stark::field::{Fp, Fp2};
use crate::shield::join::{join_split_shape, JoinSplit, Witnessed};
use crate::shield::live::*;
use crate::shield::member::PoolTree;

/// A published spend the way the live tests build one: both notes in an
/// association set the registry could have issued.
pub fn published_spend(recipient: u64) -> JoinSplit {
    let h = hasher();
    let a = note_of(A_SK, A_BLINDING, NOTE_VALUE);
    let b = note_of(B_SK, B_BLINDING, NOTE_VALUE);
    let mut at = PoolTree::with_depth(h, DEPTH);
    at.insert([Fp::from_u64(7001); RATE]);
    let ja = at.insert(commitment_of(&a));
    let jb = at.insert(commitment_of(&b));
    let oa = Witnessed {
        leaf_index: ja,
        siblings: at.path(ja).0,
    };
    let ob = Witnessed {
        leaf_index: jb,
        siblings: at.path(jb).0,
    };
    unshield_published([&oa, &ob], at.root(), recipient, 1_000_000)
}

/// A deterministic stream of field elements, so a failure reproduces.
fn stream(seed: u64) -> impl FnMut() -> Fp {
    let mut x = seed;
    move || {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        Fp::from_u64(x >> 1)
    }
}

#[test]
fn the_shape_from_the_intent_is_the_circuit_the_witness_built() {
    let js = published_spend(0x7408_ae4c);
    let real = &js.wired;
    let shape = join_split_shape(DEPTH, &js.intent);

    assert_eq!(Air::log_trace_len(real), Air::log_trace_len(&shape));
    assert_eq!(Air::trace_width(real), Air::trace_width(&shape));
    assert_eq!(Air::window_size(real), Air::window_size(&shape));
    assert_eq!(Air::constraint_degree(real), Air::constraint_degree(&shape));
    assert_eq!(Air::num_transition(real), Air::num_transition(&shape));
    assert_eq!(
        Air::boundary(real),
        Air::boundary(&shape),
        "a boundary the shape does not reproduce came from the witness"
    );
    assert_eq!(
        Air::periodic_columns(real),
        Air::periodic_columns(&shape),
        "a periodic column the shape does not reproduce came from the witness"
    );
    assert_eq!(real.group_params(), shape.group_params());
    assert_eq!(real.permutation_columns(), shape.permutation_columns());
    assert_eq!(real.group_sigmas(), shape.group_sigmas());
    assert_eq!(real.region_degrees(), shape.region_degrees());

    let w = Air::window_size(real) * Air::trace_width(real);
    let n = Air::periodic_columns(real).len();
    let mut next = stream(0x9e37_79b9_7f4a_7c15);
    for _ in 0..4 {
        let win: Vec<Fp> = (0..w).map(|_| next()).collect();
        let per: Vec<Fp> = (0..n).map(|_| next()).collect();
        assert_eq!(
            Air::transition(real, &win, &per),
            Air::transition(&shape, &win, &per),
            "a transition the shape does not reproduce came from the witness"
        );
        let win2: Vec<Fp2> = (0..w).map(|_| Fp2 { c0: next(), c1: next() }).collect();
        let per2: Vec<Fp2> = (0..n).map(|_| Fp2 { c0: next(), c1: next() }).collect();
        assert_eq!(
            AirExt::transition_ext(real, &win2, &per2),
            AirExt::transition_ext(&shape, &win2, &per2)
        );
    }
}

#[test]
fn a_different_intent_is_a_different_circuit() {
    let js = published_spend(0x7408_ae4c);
    let other = published_spend(0x1111);
    assert_ne!(js.intent, other.intent, "two recipients, one intent");
    let a = join_split_shape(DEPTH, &js.intent);
    let b = join_split_shape(DEPTH, &other.intent);
    assert_ne!(
        Air::boundary(&a),
        Air::boundary(&b),
        "the statement is pinned by the boundary, so a different statement must pin differently"
    );
    assert_eq!(Air::periodic_columns(&a), Air::periodic_columns(&b));
}
