// NONOS Operating System (AGPL-3.0-or-later)

use crate::crypto::stark::field::{Fp, Fp2};

extern crate alloc;
use alloc::vec::Vec;
#[allow(unused_imports)]
use super::{core::*, compose::*, wired_a::*, wired_b::*, codeword::*, wired_c::*};

// The second real recursion fragment: take the real Poseidon join-split proof's
// FRI layer-0 opening and prove IN-CIRCUIT (a STARK) that its Poseidon Merkle path
// authenticates against the committed root. This is verification of the real
// proof's commitment openings, arithmetized.
#[test]
fn a_real_poseidon_merkle_opening_verifies_in_circuit() {
    use crate::crypto::stark::air::{stark_prove_ext, stark_verify_ext, MultiMembership, Opening};
    use crate::crypto::stark::poseidon_merkle::pack_pair_ext;
    use crate::crypto::stark::poseidon_transcript::PoseidonTranscript;

    let h = hasher();
    let (nq, grind, extra) = (32usize, 16u32, 3u32);
    let (_air, proof) = poseidon_join_split_proof(&h, nq, grind, extra);
    let fri = &proof.fri;
    let log_n = fri_log_n(&_air, fri, extra);
    let n = 1usize << log_n;

    // Replay to the first query index.
    let mut ts = PoseidonTranscript::new(h.clone());
    // The seed the STARK transcript hands FRI, absorbed before layer zero.
    let seed = crate::crypto::stark::air::replay::replay(&_air, &proof, None, None, extra, &h, &[]).seed;
    ts.absorb(seed[0]);
    ts.absorb(seed[1]);
    for root in &fri.roots {
        ts.absorb_digest(root);
        ts.challenge_fp2();
    }
    for value in &fri.final_layer {
        ts.absorb(value.c0);
        ts.absorb(value.c1);
    }
    assert!(ts.verify_pow(fri.pow_nonce, grind));
    let q0 = ts.challenge_index(n);

    // Layer 0 opens position i = q0 % (n/2) against roots[0].
    let i = q0 % (n >> 1);
    let op = &fri.queries[0].layers[0];
    let siblings = op.path.clone();
    let depth = siblings.len();
    let directions: Vec<bool> = (0..depth).map(|l| (i >> l) & 1 == 1).collect();
    let opening = Opening {
        leaf: pack_pair_ext(op.a, op.b),
        root: fri.roots[0],
        siblings,
        directions,
    };
    let mem = MultiMembership::new(h.clone(), 2, alloc::vec![opening]);
    let mtrace = mem.trace();
    let mproof = stark_prove_ext(&mem, &mtrace, 32, 8);
    assert!(
        stark_verify_ext(&mem, &mproof, 32, 8),
        "the real Poseidon join-split proof's Merkle opening was rejected in-circuit"
    );
}

// The production form of the Merkle region: each compression's direction (boolean
// constrained) and sibling ride the trace, so the AIR is instance-independent
// (round constants, the slot and opening selectors, and the reset column are the
// only periodic columns, nothing pinned). The opened leaf and the checkpoint root
// become witness, bound by the assembly to the fold and the transcript. It
// authenticates the same real opening.
#[test]
fn the_merkle_witness_form_authenticates_the_real_opening() {
    use crate::crypto::stark::air::{
        stark_prove_ext, stark_verify_ext, Air, MultiMembership, Opening, RATE, WIDTH,
    };
    use crate::crypto::stark::poseidon_merkle::pack_pair_ext;
    use crate::crypto::stark::poseidon_transcript::PoseidonTranscript;

    let h = hasher();
    let (nq, grind, extra) = (32usize, 16u32, 3u32);
    let (_air, proof) = poseidon_join_split_proof(&h, nq, grind, extra);
    let fri = &proof.fri;
    let log_n = fri_log_n(&_air, fri, extra);
    let n = 1usize << log_n;

    let mut ts = PoseidonTranscript::new(h.clone());
    // The seed the STARK transcript hands FRI, absorbed before layer zero.
    let seed = crate::crypto::stark::air::replay::replay(&_air, &proof, None, None, extra, &h, &[]).seed;
    ts.absorb(seed[0]);
    ts.absorb(seed[1]);
    for root in &fri.roots {
        ts.absorb_digest(root);
        ts.challenge_fp2();
    }
    for value in &fri.final_layer {
        ts.absorb(value.c0);
        ts.absorb(value.c1);
    }
    assert!(ts.verify_pow(fri.pow_nonce, grind));
    let q0 = ts.challenge_index(n);

    let i = q0 % (n >> 1);
    let op = &fri.queries[0].layers[0];
    let siblings = op.path.clone();
    let depth = siblings.len();
    let directions: Vec<bool> = (0..depth).map(|l| (i >> l) & 1 == 1).collect();
    let opening = Opening {
        leaf: pack_pair_ext(op.a, op.b),
        root: fri.roots[0],
        siblings,
        directions,
    };
    let mem = MultiMembership::new_witness(h.clone(), 2, alloc::vec![opening.clone()]);
    // Instance-independent AIR: direction plus RATE sibling columns in the trace,
    // no pinned boundary.
    assert_eq!(mem.trace_width(), WIDTH + 1 + RATE);
    assert_eq!(mem.boundary().len(), 0);
    let mtrace = mem.trace();
    let mproof = stark_prove_ext(&mem, &mtrace, 32, 8);
    assert!(
        stark_verify_ext(&mem, &mproof, 32, 8),
        "the production-form Merkle opening was rejected in-circuit"
    );

    // The split form: two witnessed squares per lane appended after the
    // sibling columns, the same real opening, and the region's own degree
    // report falling from 8 to 4. It must prove and verify in-circuit like
    // the closed form it replaces in the recursion.
    let mem = MultiMembership::new_witness_split(h.clone(), 2, alloc::vec![opening]);
    assert_eq!(mem.trace_width(), WIDTH + 1 + RATE + 2 * WIDTH);
    assert_eq!(mem.constraint_degree(), 4);
    assert_eq!(mem.boundary().len(), 0);
    let mtrace = mem.trace();
    let mproof = stark_prove_ext(&mem, &mtrace, 32, 8);
    assert!(
        stark_verify_ext(&mem, &mproof, 32, 8),
        "the split-form Merkle opening was rejected in-circuit"
    );
}

// The authentication the recursion was missing: the DEEP consistency uses the
// opened DEEP value, the composition, and every trace value, and a sound verifier
// authenticates all of them against their commitments exactly as the inner
// verifier does. Deep and comp are flat, equal-depth openings; the trace row
// rides one compress-chain-plus-path opening under the wide root. This proves
// both shapes of the real proof authenticate in-circuit, so the values feeding
// the DEEP check are committed, not trusted.
#[test]
fn the_full_query_opening_set_authenticates_in_circuit() {
    use crate::crypto::stark::air::{
        query_openings_query0, stark_prove_ext, stark_verify_ext, MultiMembership, Opening,
    };
    let h = hasher();
    let (nq, grind, extra) = (32usize, 16u32, 3u32);
    let (air, proof) = poseidon_join_split_proof(&h, nq, grind, extra);
    let (openings, p) = query_openings_query0(&air, &proof, extra, &h, &[]);
    // The DEEP value and the composition; the trace row rides its own chain.
    assert_eq!(openings.len(), 2);
    /*
     * The index at full width, from the index itself. The consistency openings
     * walk a tree of fold pairs, so their directions are its low bits and one
     * short of what the trace tree needs. Copying them here walked the trace
     * tree one level shallow, which is a real row under a different root.
     */
    let cons_dirs: Vec<bool> = (0..openings[0].directions.len() + 1)
        .map(|lv| (p >> lv) & 1 == 1)
        .collect();
    let mem = MultiMembership::new_witness(h.clone(), 2, openings);
    let mtrace = mem.trace();
    let mproof = stark_prove_ext(&mem, &mtrace, 32, 8);
    assert!(
        stark_verify_ext(&mem, &mproof, 32, 8),
        "the batched query-opening authentication was rejected in-circuit"
    );

    // The wide-trace chain: the zero digest through the row's chunks, then the
    // Merkle path to the absorbed trace root, walking the same index.
    let qd = &proof.queries[0];
    let n_chunks = qd.trace.len().div_ceil(RATE);
    let mut siblings: Vec<[Fp; RATE]> = Vec::new();
    for c in 0..n_chunks {
        let mut sib = [Fp::ZERO; RATE];
        for (lane, slot) in sib.iter_mut().enumerate() {
            if let Some(v) = qd.trace.get(c * RATE + lane) {
                *slot = *v;
            }
        }
        siblings.push(sib);
    }
    siblings.extend(qd.trace_path.iter().copied());
    let mut directions = alloc::vec![false; n_chunks];
    directions.extend(cons_dirs);
    let chain = Opening {
        leaf: [Fp::ZERO; RATE],
        root: proof.trace_root,
        siblings,
        directions,
    };
    let cmem = MultiMembership::new_witness(h.clone(), 2, alloc::vec![chain]);
    let ctrace = cmem.trace();
    let cproof = stark_prove_ext(&cmem, &ctrace, 32, 8);
    assert!(
        stark_verify_ext(&cmem, &cproof, 32, 8),
        "the wide-trace chain opening was rejected in-circuit"
    );
}

// Native validation for the DEEP-x derivation: the query evaluation point x =
// shift * omega^p is not a copy of any cell, so it must be derived in-circuit from
// the consistency index p (whose bits are the deep-opening directions) as the
// product chain shift * prod_k (omega^(2^k))^(bit_k). This proves the formula and
// the bit source reproduce the real x before any constraint is written.
#[test]
fn the_deep_x_product_chain_matches_native() {
    use crate::crypto::stark::air::{deep_terms_query0, query_openings_query0};
    use crate::crypto::stark::fri::root_of_unity;
    let h = hasher();
    let (nq, grind, extra) = (32usize, 16u32, 3u32);
    let (air, proof) = poseidon_join_split_proof(&h, nq, grind, extra);
    let (_terms, dx, _ddeep) = deep_terms_query0(&air, &proof, extra, &h);

    // The deep opening's path directions are the bits of the leaf's index,
    // which is p without its top bit: the leaf holds the pair at p and at
    // p + n/2, and the top bit is the sign of the point.
    let (ops, p) = query_openings_query0(&air, &proof, extra, &h, &[]);
    let dirs = &ops[1].directions;
    let leaf: usize = dirs
        .iter()
        .enumerate()
        .map(|(lv, &b)| (b as usize) << lv)
        .sum();

    let log_n = fri_log_n(&air, &proof.fri, extra);
    let n = 1usize << log_n;
    assert_eq!(leaf, p % (n >> 1), "the directions are the leaf's index bits");
    let omega = root_of_unity(log_n);
    let shift = Fp::from_u64(7);

    let mut x = Fp2::from_base(shift);
    for k in 0..dirs.len() {
        if (leaf >> k) & 1 == 1 {
            x = x * Fp2::from_base(omega.pow(1u64 << k));
        }
    }
    let expect = if p >= (n >> 1) { Fp2::ZERO - dx } else { dx };
    assert_eq!(
        x, expect,
        "the product chain does not reproduce the real DEEP x up to its sign"
    );
}

// The DEEP-x derivation as an in-circuit region: prove the running product computes
// shift * omega^p from the index bits, and its final point equals the real DEEP x.
// The bits and the point are witness (bound by the assembly); only shift is pinned.
#[test]
fn the_index_point_region_derives_the_real_deep_x() {
    use crate::crypto::stark::air::{
        deep_terms_query0, query_openings_query0, stark_prove_ext, stark_verify_ext, IndexPoint,
    };
    use crate::crypto::stark::fri::root_of_unity;
    let h = hasher();
    let (nq, grind, extra) = (32usize, 16u32, 3u32);
    let (air, proof) = poseidon_join_split_proof(&h, nq, grind, extra);
    let (_terms, dx, _ddeep) = deep_terms_query0(&air, &proof, extra, &h);

    let (ops, p) = query_openings_query0(&air, &proof, extra, &h, &[]);
    let dirs = &ops[1].directions;
    let leaf: usize = dirs
        .iter()
        .enumerate()
        .map(|(lv, &b)| (b as usize) << lv)
        .sum();
    let bits = dirs.len();

    let log_n = fri_log_n(&air, &proof.fri, extra);
    let n = 1usize << log_n;
    let omega = root_of_unity(log_n);
    let shift = Fp::from_u64(7);

    // The region walks the leaf's bits; the top bit of p is the sign.
    let ip = IndexPoint::new(omega, shift, bits, leaf);
    let expect = if p >= (n >> 1) { Fp2::ZERO - dx } else { dx };
    assert_eq!(
        ip.point(),
        expect,
        "the region's derived point is not the real DEEP x up to its sign"
    );
    let tr = ip.trace();
    let iproof = stark_prove_ext(&ip, &tr, 32, 8);
    assert!(
        stark_verify_ext(&ip, &iproof, 32, 8),
        "the index-point derivation was rejected in-circuit"
    );
}

// The third real recursion fragment: verify the real Poseidon join-split proof's
// DEEP consistency for query 0 in-circuit -- every opened column against its
// out-of-domain claim, plus the composition against its claim, batched to the
// query's DEEP value. This is verification of the real proof's DEEP quotient,
// arithmetized.
#[test]
fn the_real_poseidon_deep_consistency_verifies_in_circuit() {
    use crate::crypto::stark::air::{
        deep_terms_query0, stark_prove_ext, stark_verify_ext, DeepCheckExt,
    };
    let h = hasher();
    let (nq, grind, extra) = (32usize, 16u32, 3u32);
    let (air, proof) = poseidon_join_split_proof(&h, nq, grind, extra);
    let (terms, x, deep) = deep_terms_query0(&air, &proof, extra, &h);
    let dc = DeepCheckExt::new(terms, x, deep);
    let dtrace = dc.trace();
    let dproof = stark_prove_ext(&dc, &dtrace, 32, 8);
    assert!(
        stark_verify_ext(&dc, &dproof, 32, 8),
        "the real Poseidon join-split proof's DEEP consistency was rejected in-circuit"
    );
}

// The production form of the DEEP region: the per-term data (val, claim, point,
// coeff) and the evaluation point x ride the trace, not periodic columns, so the
// AIR is instance-independent (the term and composition selectors are the only
// periodic columns, acc-starts-zero the only boundary). x is constrained constant
// across terms; the terms and the final DEEP value become witness, bound by the
// assembly grand product. It proves the same real DEEP consistency.
#[test]
fn the_deep_witness_form_verifies_the_real_consistency() {
    use crate::crypto::stark::air::{
        deep_terms_query0, stark_prove_ext, stark_verify_ext, Air, DeepCheckExt,
    };
    let h = hasher();
    let (nq, grind, extra) = (32usize, 16u32, 3u32);
    let (air, proof) = poseidon_join_split_proof(&h, nq, grind, extra);
    let (terms, x, deep) = deep_terms_query0(&air, &proof, extra, &h);
    let dc = DeepCheckExt::new_witness(terms, x, deep);
    // Instance-independent AIR: 16 trace columns, 3 structural periodic (two
    // selectors and the g^k schedule), 2 boundaries.
    assert_eq!(dc.trace_width(), 16);
    assert_eq!(dc.periodic_columns().len(), 3);
    assert_eq!(dc.boundary().len(), 2);
    let dtrace = dc.trace();
    let dproof = stark_prove_ext(&dc, &dtrace, 32, 8);
    assert!(
        stark_verify_ext(&dc, &dproof, 32, 8),
        "the production-form DEEP consistency was rejected in-circuit"
    );
}
