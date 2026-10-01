// NONOS Operating System (AGPL-3.0-or-later)

//! The Poseidon codec against a proof with a different value in every field.
//!
//! A codec fails by reading the right number of bytes in the wrong order, and
//! a proof built from zeros or from one repeated constant round trips through
//! every such bug. So nothing here repeats: each field gets its own value, and
//! a swap of two fields of the same width shows up as a mismatch rather than as
//! a pass.

use super::{deserialize_p_pre, deserialize_p_rounds, serialize_p_pre, serialize_p_rounds};
use crate::crypto::stark::air::{
    PeriodicOpeningP, StarkProofExtP, StarkProofExtPPre, StarkProofExtPRounds, StarkQueryExtP, RATE,
};
use crate::crypto::stark::field::{Fp, Fp2};
use crate::crypto::stark::fri_poseidon_ext::{FriProofExtP, LayerOpeningExtP, QueryProofExtP};
use alloc::vec::Vec;

/// A counter, so every field in the proof below holds a value no other field
/// holds and a transposition cannot pass.
struct Ticker(u64);

impl Ticker {
    fn fp(&mut self) -> Fp {
        self.0 += 1;
        Fp::from_u64(self.0)
    }

    fn fp2(&mut self) -> Fp2 {
        Fp2 {
            c0: self.fp(),
            c1: self.fp(),
        }
    }

    fn digest(&mut self) -> [Fp; RATE] {
        core::array::from_fn(|_| self.fp())
    }

    fn path(&mut self, depth: usize) -> Vec<[Fp; RATE]> {
        (0..depth).map(|_| self.digest()).collect()
    }
}

fn proof(t: &mut Ticker, n_queries: usize, n_layers: usize) -> StarkProofExtP {
    StarkProofExtP {
        trace_root: t.digest(),
        comp_root: t.digest(),
        ood_frame: (0..6).map(|_| t.fp2()).collect(),
        fri: FriProofExtP {
            roots: (0..n_layers).map(|_| t.digest()).collect(),
            final_layer: (0..4).map(|_| t.fp2()).collect(),
            queries: (0..n_queries)
                .map(|_| QueryProofExtP {
                    layers: (0..n_layers)
                        .map(|i| LayerOpeningExtP {
                            a: t.fp2(),
                            b: t.fp2(),
                            path: t.path(3 + i),
                        })
                        .collect(),
                })
                .collect(),
            pow_nonce: 0xDEAD_BEEF_0000_0001,
        },
        queries: (0..n_queries)
            .map(|i| StarkQueryExtP {
                deep: t.fp2(),
                deep_sib: t.fp2(),
                deep_path: t.path(5),
                trace: (0..7 + i).map(|_| t.fp()).collect(),
                trace_path: t.path(4),
                comp: t.fp2(),
                comp_sib: t.fp2(),
                comp_path: t.path(6),
            })
            .collect(),
    }
}

fn pre(t: &mut Ticker, n_queries: usize) -> StarkProofExtPPre {
    StarkProofExtPPre {
        proof: proof(t, n_queries, 3),
        periodic_z: (0..5).map(|_| t.fp2()).collect(),
        openings: (0..n_queries)
            .map(|_| PeriodicOpeningP {
                row: (0..9).map(|_| t.fp()).collect(),
                path: t.path(7),
            })
            .collect(),
    }
}

fn same_pre(a: &StarkProofExtPPre, b: &StarkProofExtPPre) {
    assert_eq!(a.proof.trace_root, b.proof.trace_root, "trace root");
    assert_eq!(a.proof.comp_root, b.proof.comp_root, "composition root");
    assert_eq!(a.proof.ood_frame, b.proof.ood_frame, "frame at z");
    assert_eq!(a.proof.fri.roots, b.proof.fri.roots, "fri roots");
    assert_eq!(a.proof.fri.final_layer, b.proof.fri.final_layer, "final layer");
    assert_eq!(a.proof.fri.pow_nonce, b.proof.fri.pow_nonce, "grind nonce");
    assert_eq!(a.proof.fri.queries.len(), b.proof.fri.queries.len(), "fri queries");
    for (x, y) in a.proof.fri.queries.iter().zip(&b.proof.fri.queries) {
        assert_eq!(x.layers.len(), y.layers.len(), "layers in a query");
        for (p, q) in x.layers.iter().zip(&y.layers) {
            assert_eq!((p.a, p.b), (q.a, q.b), "the pair a layer opens");
            assert_eq!(p.path, q.path, "the path over their shared leaf");
        }
    }
    assert_eq!(a.proof.queries.len(), b.proof.queries.len(), "consistency queries");
    for (x, y) in a.proof.queries.iter().zip(&b.proof.queries) {
        assert_eq!(
            (x.deep, x.deep_sib, &x.deep_path),
            (y.deep, y.deep_sib, &y.deep_path),
            "deep opening"
        );
        assert_eq!((&x.trace, &x.trace_path), (&y.trace, &y.trace_path), "trace row");
        assert_eq!(
            (x.comp, x.comp_sib, &x.comp_path),
            (y.comp, y.comp_sib, &y.comp_path),
            "composition"
        );
    }
    assert_eq!(a.periodic_z, b.periodic_z, "periodic claims at z");
    assert_eq!(a.openings.len(), b.openings.len(), "periodic openings");
    for (x, y) in a.openings.iter().zip(&b.openings) {
        assert_eq!((&x.row, &x.path), (&y.row, &y.path), "a periodic opening");
    }
}

#[test]
fn the_one_round_form_round_trips_field_for_field() {
    let mut t = Ticker(0);
    let p = pre(&mut t, 4);
    let bytes = serialize_p_pre(&p);
    let back = deserialize_p_pre(&bytes).expect("what this codec wrote, it reads");
    same_pre(&p, &back);
}

#[test]
fn the_two_round_form_round_trips_field_for_field() {
    let mut t = Ticker(0);
    let n_queries = 4;
    let r = StarkProofExtPRounds {
        pre: pre(&mut t, n_queries),
        perm_root: t.digest(),
        region_width: 21,
        perm_paths: (0..n_queries).map(|_| t.path(8)).collect(),
    };
    let bytes = serialize_p_rounds(&r);
    let back = deserialize_p_rounds(&bytes).expect("what this codec wrote, it reads");
    assert_eq!(back.perm_root, r.perm_root, "permutation root");
    assert_eq!(back.region_width, r.region_width, "row split");
    assert_eq!(back.perm_paths, r.perm_paths, "permutation paths");
    same_pre(&r.pre, &back.pre);
}

/// The header a decoder reads by position, pinned by offset rather than by
/// prose. A Poseidon digest is four field elements, so this is not the keccak
/// header's length and the two constants are never interchangeable.
#[test]
fn the_two_round_header_leads_with_the_permutation_root() {
    let mut t = Ticker(0);
    let r = StarkProofExtPRounds {
        pre: pre(&mut t, 2),
        perm_root: t.digest(),
        region_width: 21,
        perm_paths: (0..2).map(|_| t.path(8)).collect(),
    };
    let bytes = serialize_p_rounds(&r);
    for (i, v) in r.perm_root.iter().enumerate() {
        let at = u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().unwrap());
        assert_eq!(at, v.value(), "lane {i} of the permutation root leads");
    }
    let split = 8 * RATE;
    assert_eq!(
        u32::from_le_bytes(bytes[split..split + 4].try_into().unwrap()) as usize,
        r.region_width,
        "the row split follows the root"
    );
    let base = serialize_p_pre(&r.pre);
    assert_eq!(
        &bytes[super::P_ROUNDS_HEADER..super::P_ROUNDS_HEADER + base.len()],
        &base[..],
        "the one round encoding starts after the header and is unchanged"
    );
}

/// Truncation is the shape a relayer's half-written file arrives in, and a
/// decoder that indexes past its buffer takes the process down rather than
/// rejecting a proof.
#[test]
fn a_truncated_proof_is_refused_rather_than_panicking() {
    let mut t = Ticker(0);
    let r = StarkProofExtPRounds {
        pre: pre(&mut t, 3),
        perm_root: t.digest(),
        region_width: 21,
        perm_paths: (0..3).map(|_| t.path(8)).collect(),
    };
    let bytes = serialize_p_rounds(&r);
    for cut in [0, 1, 17, 36, 200, bytes.len() / 2, bytes.len() - 1] {
        assert!(
            deserialize_p_rounds(&bytes[..cut]).is_none(),
            "a proof cut at {cut} bytes was accepted"
        );
    }
    assert!(deserialize_p_rounds(&bytes).is_some(), "the whole proof still reads");
}

/// A length prefix is the sender's claim about how much to allocate. This one
/// says four billion rows and the buffer holds none of them.
#[test]
fn a_lying_length_prefix_allocates_nothing() {
    let mut t = Ticker(0);
    let p = pre(&mut t, 2);
    let mut bytes = serialize_p_pre(&p);
    let frame_at = 8 * RATE * 2;
    bytes[frame_at..frame_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(
        deserialize_p_pre(&bytes).is_none(),
        "a frame claiming four billion cells was accepted"
    );
}
