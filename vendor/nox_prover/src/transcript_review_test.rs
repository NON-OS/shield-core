// NONOS Operating System (AGPL-3.0-or-later)
//! Review material for the format 7 transcript: each shape's parameter-identity
//! preimage, and a transcript trace of one pinned proof replayed from its
//! bytes. Needs `stark_proofs/kat` for the trace.
//!
//!     cargo test --release -p nox_prover --features fri8,parallel,kat -- \
//!         transcript_review --ignored --nocapture
#![cfg(all(feature = "fri8", not(any(feature = "not_before", feature = "claim"))))]

use stark_proofs::crypto::stark::air::stark_verify_ext_rounds_shared_why;
use stark_proofs::crypto::stark::field::{Fp, P};
use stark_proofs::crypto::stark::fri_ext::QUERY_SHAPES;
use stark_proofs::proof_wire::{deserialize_rounds_shared, ParamSet};
use stark_proofs::shield::join::join_split_shape;
use stark_proofs::shield::member::TREE_DEPTH;
use stark_proofs::shield_params::direct;

const SPEC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../spec/transfer");

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn publics(dir: &str) -> Vec<Fp> {
    let s = std::fs::read_to_string(format!("{dir}/publics.json")).expect("publics");
    let open = s.find('[').unwrap_or(0) + 1;
    let close = s[open..].find(']').map(|i| open + i).unwrap_or(open);
    s[open..close]
        .split(',')
        .filter_map(|w| w.trim().parse().ok())
        .map(Fp::from_u64)
        .collect()
}

#[cfg(feature = "kat")]
#[test]
#[ignore = "review tier: writes spec/transfer/review"]
fn transcript_review() {
    let out = format!("{SPEC}/review");
    std::fs::create_dir_all(&out).expect("review dir");
    let words = publics(&format!("{SPEC}/transfer-eth-shape1"));
    let air = join_split_shape(TREE_DEPTH, &words);

    let mut md = String::from("# Parameter-identity preimages\n\nLayout: `NOX_PARAMS_V1` (13 bytes), then 13 u32 LE (n_queries, grind_bits, extra_blowup_bits, fri_fold_log, fri_stop_log, digest_bytes, trace_width, n_periodic, log_trace_len, constraint_degree, window_size, num_transition, n_boundary), coset_shift u64 LE, commit_grind_bits u32 LE, grind_chunks u32 LE, then the four v2 u32 LE fields: transcript version 2, DEEP grind 19, draw rule 1, shape id. Identity = keccak256(preimage).\n\n");
    for (id, q, g) in QUERY_SHAPES {
        let p = ParamSet::of(&air, q, g, direct::EXTRA_BLOWUP_BITS);
        let pre = p.preimage();
        md.push_str(&format!("## shape {id}: {q} queries, {g}-bit grind\n\n- preimage ({} bytes): `{}`\n- identity: `{}`\n- fields: {:?}\n\n", pre.len(), hex(&pre), hex(&p.id()), p));
    }
    std::fs::write(format!("{out}/PARAMS.md"), md).expect("write");

    // Trace: replay the shape 1 proof from its bytes, recording every operation.
    let (_, q, g) = QUERY_SHAPES[0];
    let params = ParamSet::of(&air, q, g, direct::EXTRA_BLOWUP_BITS);
    let bytes = std::fs::read(format!("{SPEC}/transfer-eth-shape1/proof.bin")).expect("proof");
    let root_hex = std::fs::read_to_string(format!("{SPEC}/MANIFEST.md")).expect("manifest");
    let r = root_hex
        .split("Periodic root: `")
        .nth(1)
        .and_then(|s| s.get(..64))
        .expect("root");
    let mut root = [0u8; 32];
    for i in 0..32 {
        root[i] = u8::from_str_radix(&r[2 * i..2 * i + 2], 16).expect("hex");
    }
    let (skel, streams) = deserialize_rounds_shared(&bytes, &params).expect("parses");
    let _ = stark_proofs::crypto::stark::transcript::kat::take();
    stark_verify_ext_rounds_shared_why(
        air,
        &skel,
        &streams,
        q,
        g,
        direct::EXTRA_BLOWUP_BITS,
        &root,
        &words,
    )
    .expect("verifies");
    let events = stark_proofs::crypto::stark::transcript::kat::take();
    let mut j = String::from("{\n  \"proof\": \"transfer-eth-shape1\",\n  \"note\": \"every Transcript operation of the Rust verifier replaying the proof bytes, in order: tag 0x00 new (data = label), 0x01 digest, 0x02 absorb (a vector is one event), 0x03/0x06/0x09 stream squeezes (accepted = lanes below p, in order), 0x04 query index squeeze, 0x05 nonce, 0x08 seed, 0x0A shape\",\n  \"events\": [\n");
    for (i, e) in events.iter().enumerate() {
        let lanes: Vec<String> = if matches!(e.tag, 0x03 | 0x06 | 0x09) {
            (0..4)
                .map(|k| u64::from_le_bytes(e.state[8 * k..8 * k + 8].try_into().unwrap()))
                .filter(|&w| w < P)
                .map(|w| w.to_string())
                .collect()
        } else {
            Vec::new()
        };
        let nonce = if e.tag == 0x05 && e.data.len() == 8 {
            format!(
                ", \"nonce\": {}",
                u64::from_le_bytes(e.data[..8].try_into().unwrap())
            )
        } else {
            String::new()
        };
        j.push_str(&format!(
            "    {{\"i\": {i}, \"tag\": \"0x{:02x}\", \"len\": {}, \"data\": \"{}\", \"state\": \"{}\", \"accepted\": [{}]{nonce}}}{}\n",
            e.tag,
            e.data.len(),
            if e.data.len() <= 64 { hex(&e.data) } else { format!("{}…", hex(&e.data[..32])) },
            hex(&e.state),
            lanes.join(", "),
            if i + 1 < events.len() { "," } else { "" }
        ));
    }
    j.push_str("  ]\n}\n");
    std::fs::write(format!("{out}/trace-transfer-eth-shape1.json"), j).expect("write");
    println!("{} transcript events", events.len());
}

/// The format 7 counterpart of `both_identities_are_pinned_for_the_shipped_point`:
/// the three shape identities at the launch circuit, as spec/transfer/MANIFEST.md
/// records them. A change here moves the verifier constants with it.
#[test]
fn the_three_shape_identities_are_pinned() {
    let words = vec![Fp::from_u64(0); 36];
    let air = join_split_shape(TREE_DEPTH, &words);
    let pinned = [
        "add18dbb2dba8c5426d79bca1187f6c5221a5e86108cc49ce0909d958bb5a80a",
        "7ad145c3e095bb83fb9841d0ccf3556a3349d1cf551328166770725c88f5ae44",
        "94ef16ef21b538d3e4fa340ddfea9a1ddc9afbb80c725374eaa739902e37079b",
    ];
    for ((id, q, g), want) in QUERY_SHAPES.iter().zip(pinned) {
        let p = ParamSet::of(&air, *q, *g, direct::EXTRA_BLOWUP_BITS);
        assert_eq!(hex(&p.id()), want, "shape {id}");
    }
}

fn pinned_root() -> [u8; 32] {
    let m = std::fs::read_to_string(format!("{SPEC}/MANIFEST.md")).expect("manifest");
    let r = m
        .split("Periodic root: `")
        .nth(1)
        .and_then(|s| s.get(..64))
        .expect("root");
    core::array::from_fn(|i| u8::from_str_radix(&r[2 * i..2 * i + 2], 16).expect("hex"))
}

fn words_u64(dir: &str) -> Vec<u64> {
    publics(dir).iter().map(|v| v.to_u64()).collect()
}

/// The wallet-side verify takes all four pinned transfer proofs, each at the shape
/// its header names, under the pinned periodic root.
#[test]
fn nox_prover_verifies_the_four_pinned_transfer_proofs() {
    assert_eq!(
        crate::api::PERIODIC_ROOT,
        pinned_root(),
        "the pinned root is the manifest's"
    );
    for name in [
        "transfer-eth-shape1",
        "transfer-eth-shape2",
        "transfer-eth-shape3",
        "withdraw-capped-shape1",
    ] {
        let dir = format!("{SPEC}/{name}");
        let bytes = std::fs::read(format!("{dir}/proof.bin")).expect("proof");
        crate::api::verify_shared_under(&bytes, &words_u64(&dir), &pinned_root())
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
    }
}

/// The replay behind the rank certificate and the emitters refuses a proof
/// whose DEEP nonce does not meet its grind, instead of carrying on.
#[test]
fn a_bad_deep_nonce_ends_the_replay() {
    use stark_proofs::crypto::stark::air::replay_pre::replay_comp_z_pre;
    let dir = format!("{SPEC}/transfer-eth-shape1");
    let words = publics(&dir);
    let (_, q, g) = QUERY_SHAPES[0];
    let air = join_split_shape(TREE_DEPTH, &words);
    let params = ParamSet::of(&air, q, g, direct::EXTRA_BLOWUP_BITS);
    let bytes = std::fs::read(format!("{dir}/proof.bin")).expect("proof");
    let (skel, _) = deserialize_rounds_shared(&bytes, &params).expect("parses");
    let replay = |nonce: u64| {
        let mut a = join_split_shape(TREE_DEPTH, &words);
        let mut s = skel.clone();
        s.pre.deep_nonce = nonce;
        replay_comp_z_pre(
            &mut a,
            &s.pre,
            Some(&s.perm_root),
            direct::EXTRA_BLOWUP_BITS,
            &words,
        )
        .map(|_| ())
    };
    assert_eq!(
        replay(skel.pre.deep_nonce),
        Ok(()),
        "the honest proof replays"
    );
    // Of the next 64 nonces, those that miss the 19-bit grind are refused.
    let missed: Vec<_> = (1..64u64)
        .map(|d| replay(skel.pre.deep_nonce.wrapping_add(d)))
        .filter(|r| r.is_err())
        .collect();
    assert!(!missed.is_empty());
    assert!(missed
        .iter()
        .all(|r| *r == Err("the DEEP nonce does not meet its grind")));
}

/// A proof carrying one query fewer than its shape is refused: the verifier
/// takes the query count from its own parameters, not from the proof. So is
/// the whole proof under either other shape's parameters.
#[test]
fn a_proof_with_another_query_count_is_refused() {
    let dir = format!("{SPEC}/transfer-eth-shape1");
    let words = publics(&dir);
    let (_, q, g) = QUERY_SHAPES[0];
    let air = join_split_shape(TREE_DEPTH, &words);
    let params = ParamSet::of(&air, q, g, direct::EXTRA_BLOWUP_BITS);
    let bytes = std::fs::read(format!("{dir}/proof.bin")).expect("proof");
    let (mut skel, streams) = deserialize_rounds_shared(&bytes, &params).expect("parses");
    skel.pre.proof.fri.queries.pop();
    skel.pre.proof.queries.pop();
    skel.pre.openings.pop();
    skel.perm_paths.pop();
    let root = pinned_root();
    let v = join_split_shape(TREE_DEPTH, &words);
    assert!(stark_verify_ext_rounds_shared_why(
        v,
        &skel,
        &streams,
        q,
        g,
        direct::EXTRA_BLOWUP_BITS,
        &root,
        &words
    )
    .is_err());
    let (skel, streams) = deserialize_rounds_shared(&bytes, &params).expect("parses");
    for (_, q2, g2) in &QUERY_SHAPES[1..] {
        let v = join_split_shape(TREE_DEPTH, &words);
        assert!(stark_verify_ext_rounds_shared_why(
            v,
            &skel,
            &streams,
            *q2,
            *g2,
            direct::EXTRA_BLOWUP_BITS,
            &root,
            &words
        )
        .is_err());
    }
}
