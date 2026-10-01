// NONOS Operating System (AGPL-3.0-or-later)

use crate::crypto::stark::field::{Fp, Fp2};
use crate::crypto::stark::fri_poseidon_ext::{fri_prove_poseidon_ext, fri_verify_poseidon_ext};

extern crate alloc;
use alloc::vec::Vec;
#[allow(unused_imports)]
use super::{core::*, openings::*, compose::*, wired_a::*, wired_b::*, wired_c::*};

// The publics-binding reference: a batch's K*11 per-intent public words are absorbed
// into the transcript's inject column (the FS input column the pool reads), proven in
// circuit, with word j of intent i landing at row (i*11+j)*l. This is the layout the
// pool's settleBatch extraction indexes; the production vector rides this same column,
// with the words being the real batch publics the inner join-split proof absorbs.
#[test]
#[ignore]
fn gen_publics_bound_reference() {
    use crate::crypto::stark::air::{stark_prove_ext, stark_verify_ext, Air, TranscriptCheck, INJECT, RATE};
    use crate::recursion_assembly::sponge::Recorder;
    use alloc::string::String;

    let h = hasher();
    let k_intents = 2usize;
    let words = 11usize;
    let l = 4usize; // permutation rounds

    // Representative per-intent publics in the frozen 11-word order.
    let mut publics: Vec<Fp> = Vec::with_capacity(k_intents * words);
    for i in 0..k_intents {
        for j in 0..words {
            publics.push(Fp::from_u64(0x9000 + (i * words + j) as u64));
        }
    }

    // The transcript absorbs every public word, then squeezes a binding challenge so
    // the challenge depends on the whole batch statement.
    let mut r = Recorder::new(&h);
    for &p in &publics {
        r.absorb(p);
    }
    r.challenge();
    r.challenge();

    let tc = TranscriptCheck::new(h.clone(), 2, r.finish());
    let ttrace = tc.trace();
    let bad = crate::witness_satisfies::violations(&tc, &ttrace, 4);
    assert!(bad.is_empty(), "the publics-bound transcript breaks its own AIR at (row, lane) {bad:?}");
    let proof = stark_prove_ext(&tc, &ttrace, 32, 8);
    assert!(
        stark_verify_ext(&tc, &proof, 32, 8),
        "the publics-bound transcript was rejected"
    );

    // The FS input columns are the inject periodic columns from INJECT; word
    // j of intent i is word w = i*11+j, at row (w/4)*l in column INJECT + w%4.
    let mut pubs_json = String::from("[");
    for (idx, p) in publics.iter().enumerate() {
        if idx > 0 {
            pubs_json.push(',');
        }
        let (i, j) = (idx / words, idx % words);
        pubs_json.push_str(&alloc::format!(
            "[{},{},{},{},\"{}\"]",
            i,
            j,
            ((i * words + j) / RATE) * l,
            INJECT + (i * words + j) % RATE,
            p.value()
        ));
    }
    pubs_json.push(']');

    let bytes = crate::stark_selftest_gen::serialize(&proof);
    let json = alloc::format!(
        "{{\n  \"engine\": \"nonos-money-grade-stark\",\n  \"artifact\": \"publics-bound-reference\",\n  \"note\": \"Reference for the pool publics binding. K*11 per-intent public words absorbed into the transcript inject columns (the FS input columns), four to a block, proven in circuit. word w = i*11+j of intent i is at row (w/4)*l, column fs_input_column_index + w%4; each entry is [i, j, row, column, value]. The production vector is this same column carrying the real batch publics that the inner join-split proof absorbs, wired into the assembled recursion.\",\n  \"l\": {},\n  \"fs_input_column_index\": {},\n  \"k_intents\": {},\n  \"words_per_intent\": {},\n  \"trace_width\": {},\n  \"publics\": {},\n  \"proof_len_bytes\": {},\n  \"proof_hex\": \"{}\"\n}}\n",
        l, INJECT, k_intents, words, tc.trace_width(), pubs_json, bytes.len(),
        crate::stark_selftest_gen::hex(&bytes)
    );
    crate::spec_out::write_spec("publics-bound-reference.json", &json);
    std::println!(
        "wrote publics-bound reference: {} publics, {} proof bytes",
        publics.len(),
        bytes.len()
    );
}

#[test]
fn a_poseidon_committed_stark_holds_at_deployment_blowup() {
    use crate::crypto::stark::air::{
        stark_prove_poseidon_ext, stark_verify_poseidon_ext, Squaring,
    };
    // rate 1/16 (extra_blowup_bits = 3): the inner proof at deployment soundness.
    let seed = Fp::from_u64(5);
    let air = Squaring { log_t: 4, seed };
    let trace = squaring_trace(4, seed);
    let h = hasher();
    let proof = stark_prove_poseidon_ext(&air, &trace, 32, 16, 3, &h);
    assert!(
        stark_verify_poseidon_ext(&air, &proof, 32, 16, 3, &h),
        "an honest deployment-soundness Poseidon STARK was rejected"
    );
}

#[test]
fn a_low_degree_poseidon_ext_codeword_verifies() {
    let (log_n, log_blowup) = (10u32, 1u32);
    let shift = Fp::from_u64(7);
    let d = 1usize << (log_n - log_blowup);
    let cw = low_degree_ext(log_n, d, shift, 0xABCD_1234);
    let h = hasher();
    let proof = fri_prove_poseidon_ext(&cw, shift, log_blowup, 32, 8, &h);
    assert!(
        fri_verify_poseidon_ext(&proof, shift, log_n, log_blowup, 32, 8, &h),
        "an honest low-degree Poseidon extension codeword was rejected"
    );
}

#[test]
fn a_high_degree_poseidon_ext_codeword_is_rejected() {
    let (log_n, log_blowup) = (10u32, 1u32);
    let shift = Fp::from_u64(7);
    // Degree equal to the domain size: not low degree for a rate-1/2 test.
    let cw = low_degree_ext(log_n, 1usize << log_n, shift, 0x9999);
    let h = hasher();
    let proof = fri_prove_poseidon_ext(&cw, shift, log_blowup, 32, 8, &h);
    assert!(
        !fri_verify_poseidon_ext(&proof, shift, log_n, log_blowup, 32, 8, &h),
        "a high-degree Poseidon extension codeword verified"
    );
}

#[test]
fn a_tampered_final_layer_is_rejected() {
    let (log_n, log_blowup) = (10u32, 1u32);
    let shift = Fp::from_u64(7);
    let d = 1usize << (log_n - log_blowup);
    let cw = low_degree_ext(log_n, d, shift, 0x5151);
    let h = hasher();
    let mut proof = fri_prove_poseidon_ext(&cw, shift, log_blowup, 32, 8, &h);
    proof.final_layer[0] = proof.final_layer[0] + Fp2::from_base(Fp::from_u64(1));
    assert!(
        !fri_verify_poseidon_ext(&proof, shift, log_n, log_blowup, 32, 8, &h),
        "a tampered final layer verified"
    );
}
