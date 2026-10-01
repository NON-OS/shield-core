// NONOS Operating System (AGPL-3.0-or-later)
#![cfg(feature = "launch_v1")]
//! Format 6 on the pinned launch transfer: the same proof with its paths
//! shared, verified by the same verifier, and refused when touched.

use crate::crypto::stark::air::domain_params_blown;
use crate::crypto::stark::air::{
    fill_shared_paths, periodic_root, share_paths, stark_verify_ext_rounds_positions,
    stark_verify_ext_rounds_shared_why, SharedPaths, StarkProofExtRounds,
};
use crate::crypto::stark::field::Fp;
use crate::crypto::stark::merkle::DIGEST_BYTES;
use crate::proof_wire::{
    deserialize_rounds, deserialize_rounds_shared, serialize_rounds_shared, ParamSet, HEADER_BYTES,
};
use crate::shield::join::join_split_shape;
use crate::shield::member::TREE_DEPTH;
use crate::shield_params::direct;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::OnceLock;

const PROOF: &[u8] = include_bytes!("../../spec/wallet-vectors/transfer-eth/proof.bin");
const PUBLICS: &str = include_str!("../../spec/wallet-vectors/transfer-eth/publics.json");
const POINT: (usize, u32, u32) = (
    direct::N_QUERIES,
    direct::GRIND_BITS,
    direct::EXTRA_BLOWUP_BITS,
);

fn words() -> Vec<Fp> {
    let open = PUBLICS.find('[').unwrap_or(0) + 1;
    let close = PUBLICS[open..].find(']').map(|i| open + i).unwrap_or(open);
    PUBLICS[open..close]
        .split(',')
        .filter_map(|w| w.trim().parse().ok())
        .map(Fp::from_u64)
        .collect()
}

fn params() -> ParamSet {
    ParamSet::of(
        &join_split_shape(TREE_DEPTH, &words()),
        POINT.0,
        POINT.1,
        POINT.2,
    )
}

fn root() -> &'static [u8; 32] {
    static ROOT: OnceLock<[u8; 32]> = OnceLock::new();
    ROOT.get_or_init(|| periodic_root(&join_split_shape(TREE_DEPTH, &words()), POINT.2))
}

fn log_n() -> u32 {
    domain_params_blown(&join_split_shape(TREE_DEPTH, &words()), POINT.2).0
}

/// The pinned proof, its positions, its streams and its format 6 bytes.
struct Converted {
    rounds: StarkProofExtRounds,
    positions: Vec<usize>,
    shared: SharedPaths,
    bytes: Vec<u8>,
}

fn converted() -> &'static Converted {
    static C: OnceLock<Converted> = OnceLock::new();
    C.get_or_init(|| {
        let w = words();
        let rounds = deserialize_rounds(PROOF, &params()).expect("the pinned proof parses");
        let air = join_split_shape(TREE_DEPTH, &w);
        let positions =
            stark_verify_ext_rounds_positions(air, &rounds, POINT.0, POINT.1, POINT.2, root(), &w)
                .expect("the pinned proof verifies");
        let shared = share_paths(&rounds, &positions, log_n()).expect("its paths share");
        let bytes = serialize_rounds_shared(&rounds, &shared, &params());
        Converted {
            rounds,
            positions,
            shared,
            bytes,
        }
    })
}

fn verdict(bytes: &[u8]) -> Result<(), String> {
    let w = words();
    let run = || {
        let (skeleton, shared) = deserialize_rounds_shared(bytes, &params())
            .ok_or_else(|| "does not parse".to_string())?;
        let air = join_split_shape(TREE_DEPTH, &w);
        stark_verify_ext_rounds_shared_why(
            air,
            &skeleton,
            &shared,
            POINT.0,
            POINT.1,
            POINT.2,
            root(),
            &w,
        )
        .map_err(|why| why.to_string())
    };
    match catch_unwind(AssertUnwindSafe(run)) {
        Ok(v) => v,
        Err(_) => panic!("the format 6 check panicked on {} bytes", bytes.len()),
    }
}

#[test]
fn the_shared_proof_verifies_and_is_smaller() {
    let c = converted();
    assert_eq!(verdict(&c.bytes), Ok(()));
    let streams: usize = c.shared.fri.iter().map(Vec::len).sum::<usize>()
        + c.shared.trace.len()
        + c.shared.perm.len()
        + c.shared.comp.len()
        + c.shared.periodic.len();
    println!(
        "format 5 {} bytes, format 6 {} bytes, {} saved; {} shared digests, per tree fri {:?} trace {} perm {} comp {} periodic {}",
        PROOF.len(),
        c.bytes.len(),
        PROOF.len() - c.bytes.len(),
        streams,
        c.shared.fri.iter().map(Vec::len).collect::<Vec<_>>(),
        c.shared.trace.len(),
        c.shared.perm.len(),
        c.shared.comp.len(),
        c.shared.periodic.len()
    );
    assert!(c.bytes.len() < PROOF.len());
    println!("positions {:?}", c.positions);
}

/// Filling the streams back gives format 5's paths exactly, and the byte
/// count is format 5's less every path digest and path length word, less the
/// per query counts format 6 drops, plus one count per stream and its digests.
#[test]
fn the_streams_expand_to_the_paths_they_replaced() {
    let c = converted();
    let back =
        fill_shared_paths(&c.rounds, &c.shared, &c.positions, log_n()).expect("the streams expand");
    let (a, b) = (&c.rounds.pre, &back.pre);
    for (x, y) in a.proof.queries.iter().zip(&b.proof.queries) {
        assert_eq!(x.trace_path, y.trace_path);
        assert_eq!(x.comp_path, y.comp_path);
    }
    for (x, y) in a.proof.fri.queries.iter().zip(&b.proof.fri.queries) {
        for (l, m) in x.layers.iter().zip(&y.layers) {
            assert_eq!(l.path, m.path);
        }
    }
    for (x, y) in a.openings.iter().zip(&b.openings) {
        assert_eq!(x.path, y.path);
    }
    assert_eq!(c.rounds.perm_paths, back.perm_paths);

    let n_q = c.positions.len();
    let n_layers = c.shared.fri.len();
    let mut path_digests = 0usize;
    for q in &a.proof.queries {
        path_digests += q.trace_path.len() + q.comp_path.len();
    }
    for q in &a.proof.fri.queries {
        path_digests += q.layers.iter().map(|l| l.path.len()).sum::<usize>();
    }
    path_digests += a.openings.iter().map(|o| o.path.len()).sum::<usize>();
    path_digests += c.rounds.perm_paths.iter().map(Vec::len).sum::<usize>();
    let path_words = n_q * (n_layers + 4);
    let dropped_counts = n_q /* fri layer counts */ + n_q /* trace lengths */ + 1 /* query count */;
    let streams = n_layers + 4;
    let stream_digests: usize = c.shared.fri.iter().map(Vec::len).sum::<usize>()
        + c.shared.trace.len()
        + c.shared.perm.len()
        + c.shared.comp.len()
        + c.shared.periodic.len();
    let expect = PROOF.len() - DIGEST_BYTES * path_digests - 4 * path_words - 4 * dropped_counts
        + 4 /* row width */
        + 4 * streams
        + DIGEST_BYTES * stream_digests;
    assert_eq!(c.bytes.len(), expect, "the byte count is not the spec's");
}

#[test]
fn no_single_flipped_bit_verifies() {
    let bytes = &converted().bytes;
    let body = bytes.len() - HEADER_BYTES;
    let mut at: Vec<usize> = (0..HEADER_BYTES).collect();
    at.extend((0..240).map(|k| HEADER_BYTES + k * body / 240 + (k * 7919) % (body / 240)));
    for (n, &i) in at.iter().enumerate() {
        let mut b = bytes.clone();
        b[i] ^= if n % 2 == 0 { 0x01 } else { 0x80 };
        assert!(
            verdict(&b).is_err(),
            "byte {i} flipped and the proof still verified"
        );
    }
}

/// Every stream digest flipped, one at a time: a sibling is read by exactly
/// one walk, so changing any of them must be caught.
#[test]
fn every_stream_digest_is_bound() {
    let c = converted();
    let streams = c.shared.fri.iter().map(Vec::len).sum::<usize>()
        + c.shared.trace.len()
        + c.shared.perm.len()
        + c.shared.comp.len()
        + c.shared.periodic.len();
    let tail = c.bytes.len();
    let n_streams = c.shared.fri.len() + 4;
    let start = tail - DIGEST_BYTES * streams - 4 * n_streams;
    let mut i = start;
    let mut checked = 0usize;
    for s in c.shared.fri.iter().chain([
        &c.shared.trace,
        &c.shared.perm,
        &c.shared.comp,
        &c.shared.periodic,
    ]) {
        i += 4;
        for _ in 0..s.len() {
            let mut b = c.bytes.clone();
            b[i + (checked % DIGEST_BYTES)] ^= 0x10;
            assert!(
                verdict(&b).is_err(),
                "stream digest at {i} changed and the proof still verified"
            );
            i += DIGEST_BYTES;
            checked += 1;
        }
    }
    assert_eq!(i, tail);
    assert_eq!(checked, streams);
}

#[test]
fn a_cut_padded_or_regrown_stream_does_not_verify() {
    let c = converted();
    for len in [0, HEADER_BYTES, c.bytes.len() / 2, c.bytes.len() - 1] {
        assert!(
            verdict(&c.bytes[..len]).is_err(),
            "cut to {len} bytes and verified"
        );
    }
    let mut pad = c.bytes.clone();
    pad.push(0);
    assert!(verdict(&pad).is_err(), "a trailing byte verified");

    // The periodic stream, last on the wire, one digest longer with its count
    // raised to match: it parses, and the verifier refuses the extra sibling.
    let mut long = c.bytes.clone();
    let n = c.shared.periodic.len();
    let count_at = long.len() - DIGEST_BYTES * n - 4;
    long[count_at..count_at + 4].copy_from_slice(&((n + 1) as u32).to_le_bytes());
    long.extend_from_slice(&[0u8; DIGEST_BYTES]);
    assert!(deserialize_rounds_shared(&long, &params()).is_some());
    assert_eq!(
        verdict(&long),
        Err("a shared path stream refused".to_string())
    );
}

/// Each reader decodes its own format and no other.
#[test]
fn formats_five_and_six_do_not_cross() {
    let c = converted();
    assert!(deserialize_rounds_shared(PROOF, &params()).is_none());
    assert!(deserialize_rounds(&c.bytes, &params()).is_none());
}
