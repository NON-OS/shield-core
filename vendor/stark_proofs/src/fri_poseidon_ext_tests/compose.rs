// NONOS Operating System (AGPL-3.0-or-later)

use crate::crypto::stark::field::Fp;
use crate::crypto::stark::fri::root_of_unity;

extern crate alloc;
use alloc::vec::Vec;
#[allow(unused_imports)]
use super::{core::*, openings::*, wired_a::*, wired_b::*, codeword::*, wired_c::*};

// The inlined compose_ext formula for the join-split, validated natively against
// the real compose_ext: this pins the arithmetic the compose-at-z AIR must encode
// (transition values out0..out2, the exempt/vanishing factor, boundary quotients)
// before it is committed to constraints.
#[test]
fn the_join_split_compose_formula_matches_compose_ext() {
    use crate::crypto::stark::air::{compose_inputs, Air};
    use crate::crypto::stark::field::Fp2;

    let h = hasher();
    let (nq, grind, extra) = (32usize, 16u32, 3u32);
    let (air, proof) = poseidon_join_split_proof(&h, nq, grind, extra);
    let ci = compose_inputs(&air, &proof, extra, &h);

    let t = 1u64 << air.log_trace_len();
    let g = root_of_unity(air.log_trace_len());
    let w = &proof.ood_frame;
    let (w0, w1, w2, w3, w5) = (w[0], w[1], w[2], w[3], w[5]);
    let p = &ci.periodic_z;
    let (sel0, sel1, id, sig, gp_sel) = (p[0], p[1], p[2], p[3], p[4]);
    let beta = Fp2::from_base(Fp::from_u64(5));
    let gamma = Fp2::from_base(Fp::from_u64(7));
    let two = Fp2::from_base(Fp::from_u64(2));

    let out0 = sel0 * (w3 - w0 - w1) + sel1 * (w0 - two * w3 - w1);
    let out1 = sel1 * (w1 * (w1 - Fp2::ONE));
    let num = w0 + beta * id + gamma;
    let den = w0 + beta * sig + gamma;
    let out2 = gp_sel * (w5 * den - w2 * num) + (Fp2::ONE - gp_sel) * (w5 - w2);

    let z = ci.z;
    let z_h_inv = (z.pow(t) - Fp2::ONE).inv();
    let exempt = z - Fp2::from_base(g.pow(t - 1));
    let e = exempt * z_h_inv;

    let mut acc = ci.coeffs[0] * out0 * e + ci.coeffs[1] * out1 * e + ci.coeffs[2] * out2 * e;
    for (j, (col, row, expected)) in air.boundary().iter().enumerate() {
        let q =
            (w[*col] - Fp2::from_base(*expected)) * (z - Fp2::from_base(g.pow(*row as u64))).inv();
        acc = acc + ci.coeffs[3 + j] * q;
    }
    assert_eq!(
        acc, ci.comp_z,
        "the inlined join-split compose formula did not match compose_ext"
    );
}

// The fourth and hardest recursion fragment: verify compose_ext AT z in-circuit
// over the real proof -- the meta-circular piece that re-derives the composition
// value the DEEP check consumes from the out-of-domain frame, arithmetizing the
// join-split's own transition_ext plus the vanishing and boundary quotients. With
// this the composition value is no longer trusted; it is proven.
#[test]
fn the_real_poseidon_compose_at_z_verifies_in_circuit() {
    use crate::crypto::stark::air::{
        compose_inputs, stark_prove_ext, stark_verify_ext, Air, ComposeBoundary, ComposeCheck,
    };
    use crate::crypto::stark::field::Fp2;

    let h = hasher();
    let (nq, grind, extra) = (32usize, 16u32, 3u32);
    let (air, proof) = poseidon_join_split_proof(&h, nq, grind, extra);
    let ci = compose_inputs(&air, &proof, extra, &h);
    let t = 1u64 << air.log_trace_len();
    let g = root_of_unity(air.log_trace_len());

    let mut window = [Fp2::ZERO; 6];
    window.copy_from_slice(&proof.ood_frame[..6]);
    let mut periodic = [Fp2::ZERO; 5];
    periodic.copy_from_slice(&ci.periodic_z[..5]);
    let mut coeffs = [Fp2::ZERO; 8];
    coeffs.copy_from_slice(&ci.coeffs[..8]);
    let boundaries: Vec<ComposeBoundary> = air
        .boundary()
        .iter()
        .map(|(col, row, expected)| ComposeBoundary {
            col: *col,
            g_row: g.pow(*row as u64),
            expected: *expected,
        })
        .collect();

    let cc = ComposeCheck::new(
        window,
        periodic,
        coeffs,
        ci.z,
        ci.comp_z,
        g.pow(t - 1),
        t,
        boundaries,
    );
    let ctrace = cc.trace();
    let cproof = stark_prove_ext(&cc, &ctrace, 32, 8);
    assert!(
        stark_verify_ext(&cc, &cproof, 32, 8),
        "the real proof's compose_ext at z was rejected in-circuit"
    );
}

// The compose-at-z check must reject a composition value that is not the honest
// combination of the frame: a prover cannot substitute a convenient comp_z.
#[test]
fn the_real_poseidon_compose_at_z_rejects_a_wrong_value() {
    use crate::crypto::stark::air::{
        compose_inputs, stark_prove_ext, stark_verify_ext, Air, ComposeBoundary, ComposeCheck,
    };
    use crate::crypto::stark::field::Fp2;

    let h = hasher();
    let (nq, grind, extra) = (32usize, 16u32, 3u32);
    let (air, proof) = poseidon_join_split_proof(&h, nq, grind, extra);
    let ci = compose_inputs(&air, &proof, extra, &h);
    let t = 1u64 << air.log_trace_len();
    let g = root_of_unity(air.log_trace_len());

    let mut window = [Fp2::ZERO; 6];
    window.copy_from_slice(&proof.ood_frame[..6]);
    let mut periodic = [Fp2::ZERO; 5];
    periodic.copy_from_slice(&ci.periodic_z[..5]);
    let mut coeffs = [Fp2::ZERO; 8];
    coeffs.copy_from_slice(&ci.coeffs[..8]);
    let boundaries: Vec<ComposeBoundary> = air
        .boundary()
        .iter()
        .map(|(col, row, expected)| ComposeBoundary {
            col: *col,
            g_row: g.pow(*row as u64),
            expected: *expected,
        })
        .collect();

    let wrong = ci.comp_z + Fp2::from_base(Fp::from_u64(1));
    let cc = ComposeCheck::new(
        window,
        periodic,
        coeffs,
        ci.z,
        wrong,
        g.pow(t - 1),
        t,
        boundaries,
    );
    let ctrace = cc.trace();
    let cproof = stark_prove_ext(&cc, &ctrace, 32, 8);
    assert!(
        !stark_verify_ext(&cc, &cproof, 32, 8),
        "a dishonest composition value verified"
    );
}

// Pin the exact sponge alignment before arithmetizing it: a hand-run Poseidon
// duplex at the rate (absorb = add into the next lane, permute when four are
// in; squeeze = permute a partial block, read lanes 0 and 1, permute) must
// reproduce the real proof's STARK challenges bit for bit. This is the ground
// truth the transcript-derivation AIR must match.
#[test]
fn the_transcript_sponge_reproduces_the_stark_challenges() {
    use crate::crypto::stark::air::{compose_inputs, Poseidon, RATE, WIDTH};
    use crate::crypto::stark::field::Fp2;

    fn absorb(h: &Poseidon, st: &mut [Fp; WIDTH], pending: &mut usize, v: Fp) {
        st[*pending] = st[*pending] + v;
        *pending += 1;
        if *pending == RATE {
            *st = h.permute(*st);
            *pending = 0;
        }
    }
    fn squeeze(h: &Poseidon, st: &mut [Fp; WIDTH], pending: &mut usize) -> Fp2 {
        if *pending > 0 {
            *st = h.permute(*st);
            *pending = 0;
        }
        let c = Fp2::new(st[0], st[1]);
        *st = h.permute(*st);
        c
    }

    let h = hasher();
    let (nq, grind, extra) = (32usize, 16u32, 3u32);
    let (air, proof) = poseidon_join_split_proof(&h, nq, grind, extra);
    let ci = compose_inputs(&air, &proof, extra, &h);

    let mut st = [Fp::ZERO; WIDTH];
    let mut pending = 0usize;
    for lane in &proof.trace_root {
        absorb(&h, &mut st, &mut pending, *lane);
    }
    // One squeeze for the composition alpha; the coefficients are its powers.
    let alpha = squeeze(&h, &mut st, &mut pending);
    let mut coeffs = Vec::with_capacity(ci.coeffs.len());
    let mut p = Fp2::ONE;
    for _ in 0..ci.coeffs.len() {
        coeffs.push(p);
        p = p * alpha;
    }
    assert_eq!(coeffs, ci.coeffs, "the hand-run sponge did not reproduce the coefficients");

    for lane in &proof.comp_root {
        absorb(&h, &mut st, &mut pending, *lane);
    }
    let z = squeeze(&h, &mut st, &mut pending);
    assert_eq!(z, ci.z, "the hand-run sponge did not reproduce the out-of-domain point");
}

// The fifth recursion fragment: prove the real proof's Fiat-Shamir challenges were
// honestly squeezed from its committed data, in-circuit. The absorbed sequence is
// the proof's (trace roots, composition root, out-of-domain frame); the squeezed
// coefficients, out-of-domain point, and DEEP coefficients are pinned. With this
// the challenges are proven, not trusted.
#[test]
fn the_real_poseidon_transcript_derivation_verifies_in_circuit() {
    use crate::crypto::stark::air::{stark_prove_ext, stark_verify_ext, TranscriptCheck};
    use crate::recursion_assembly::sponge::Recorder;

    let h = hasher();
    let (nq, grind, extra) = (32usize, 16u32, 3u32);
    let (_air, proof) = poseidon_join_split_proof(&h, nq, grind, extra);

    let mut r = Recorder::new(&h);
    r.absorb_digest(&proof.trace_root);
    // The composition alpha, then z, then the DEEP alpha: one operation each.
    r.challenge_fp2();
    r.absorb_digest(&proof.comp_root);
    r.challenge_fp2();
    for v in &proof.ood_frame {
        r.absorb(v.c0);
        r.absorb(v.c1);
    }
    r.challenge_fp2();

    let tc = TranscriptCheck::new(h.clone(), 2, r.finish());
    let ttrace = tc.trace();
    let tproof = stark_prove_ext(&tc, &ttrace, 32, 8);
    assert!(
        stark_verify_ext(&tc, &tproof, 32, 8),
        "the real proof's transcript derivation was rejected in-circuit"
    );
}

// The production form of the transcript region: the absorbed value rides the trace,
// gated by a structural inject selector, and no squeeze is pinned. The AIR is then
// instance-independent (round constants and the selector are the only periodic
// columns, sponge-empty the only boundaries), which is what a fixed on-chain
// verifier needs. The absorbed values and squeezed challenges become witness, bound
// by the assembly grand product to their sources and consumers.
#[test]
fn the_transcript_witness_form_proves_the_same_sponge_without_pinning() {
    use crate::crypto::stark::air::{stark_prove_ext, stark_verify_ext, Air, TranscriptCheck, RATE, WIDTH};
    use crate::recursion_assembly::sponge::Recorder;
    let h = hasher();
    let mut r = Recorder::new(&h);
    for i in 0..6u64 {
        r.absorb(Fp::from_u64(7 * i + 1));
    }
    for _ in 0..4 {
        r.challenge();
    }

    let tc = TranscriptCheck::new_witness(h.clone(), 2, r.finish());
    // Four inject columns and the squares beside the state; the AIR is
    // instance-independent.
    assert_eq!(tc.trace_width(), WIDTH + RATE + 2 * WIDTH);
    assert_eq!(tc.periodic_columns().len(), WIDTH + 1);
    assert_eq!(
        tc.boundary().len(),
        WIDTH,
        "only the sponge-empty boundaries remain"
    );
    let tr = tc.trace();
    // Native check first: every transition row must vanish, boundaries must hold.
    let w = tc.trace_width();
    let n = 1usize << tc.log_trace_len();
    let per = tc.periodic_columns();
    for row in 0..n - 1 {
        let window: Vec<Fp> = tr[row * w..(row + 2) * w].to_vec();
        let pr: Vec<Fp> = per.iter().map(|c| c[row]).collect();
        let out = tc.transition(&window, &pr);
        assert!(
            out.iter().all(|v| *v == Fp::ZERO),
            "witness transition nonzero at row {}: {:?}",
            row,
            out
        );
    }
    let proof = stark_prove_ext(&tc, &tr, 32, 8);
    assert!(
        stark_verify_ext(&tc, &proof, 32, 8),
        "the production-form transcript sponge did not verify"
    );
}
