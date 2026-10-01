// NONOS Operating System (AGPL-3.0-or-later)

use crate::crypto::stark::field::Fp;
use crate::crypto::stark::fri::root_of_unity;

extern crate alloc;
use alloc::vec::Vec;
#[allow(unused_imports)]
use super::{core::*, openings::*, compose::*, wired_b::*, codeword::*, wired_c::*};

// The assembly begins: wire the transcript-derivation region and the compose-at-z
// region into ONE proof, binding the squeezed out-of-domain point to the point the
// composition is evaluated at. So compose no longer trusts z; it is the z the
// transcript proved was squeezed. The grand product over the shared cells is the
// copy constraint.
#[ignore]
#[test]
fn the_transcript_and_compose_are_wired_into_one_proof() {
    use crate::crypto::stark::air::{
        compose_inputs, AlphaPowers, stark_prove_ext, stark_verify_ext, Air, AirExt, ComposeBoundary,
        ComposeCheck, TranscriptCheck, WiredExt,
    };
    use crate::crypto::stark::field::Fp2;
    use crate::recursion_assembly::sponge::Recorder;
    use alloc::boxed::Box;

    let h = hasher();
    let (nq, grind, extra) = (32usize, 16u32, 3u32);
    let (air, proof) = poseidon_join_split_proof(&h, nq, grind, extra);
    let ci = compose_inputs(&air, &proof, extra, &h);
    let t = 1u64 << air.log_trace_len();
    let g = root_of_unity(air.log_trace_len());

    // Region 1: compose-at-z.
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
    let compose = ComposeCheck::new(
        window,
        periodic,
        coeffs,
        ci.z,
        ci.comp_z,
        g.pow(t - 1),
        t,
        boundaries,
    );
    let ctrace = compose.trace();

    // Region 0: transcript derivation. z is squeezed at operations after the trace
    // roots, the coefficients, and the composition root.
    let mut r = Recorder::new(&h);
    r.absorb_digest(&proof.trace_root);
    // The composition alpha, one operation; the coefficients are its powers
    // and ride their own region below.
    let (coeff_op, _) = r.challenge_fp2();
    r.absorb_digest(&proof.comp_root);
    let (z_op, _) = r.challenge_fp2();
    let transcript = TranscriptCheck::new(h.clone(), 2, r.finish());
    let ttrace = transcript.trace();

    // Region 2: the composition coefficients as powers of the squeezed alpha.
    let powers = AlphaPowers::new(ci.coeffs[1], ci.coeffs.len());
    let ptrace = powers.trace();
    let regions: Vec<Box<dyn AirExt>> = alloc::vec![
        Box::new(transcript) as Box<dyn AirExt>,
        Box::new(compose),
        Box::new(powers),
    ];
    let l = 4usize; // permutation rounds
    let t_height = 1usize << regions[0].log_trace_len();
    let p_off = t_height + (1usize << regions[1].log_trace_len());
    let span = (p_off + (1usize << regions[2].log_trace_len())).next_power_of_two();

    // wired columns: the transcript squeeze lane (0) and compose's z (22, 23) and
    // coefficient cells (24..39).
    let mut wired_cols = alloc::vec![0usize, 1, 2, 3];
    for c in 22..40 {
        wired_cols.push(c);
    }
    let k = wired_cols.len();
    let widx = |col: usize| -> usize { wired_cols.iter().position(|&c| c == col).unwrap() };
    let mut sigma: Vec<usize> = (0..span * k).collect();
    let c_row = t_height; // compose region row 0
                          // z: transcript operations z_op, z_op+1 wire to compose columns 22, 23.
    sigma.swap((z_op * l) * k, c_row * k + widx(22));
    sigma.swap((z_op * l) * k + widx(1), c_row * k + widx(23));
    // The 8 coefficients, each squeezed as a pair from `coeff_op` (after the root
    // absorbs) wire to compose columns 24+2i, 25+2i.
    // alpha: the two squeezes at `coeff_op` wire to the powers region's alpha
    // cells; each coefficient cell wires to its power, row i of that region.
    sigma.swap((coeff_op * l) * k, p_off * k + widx(2));
    sigma.swap((coeff_op * l) * k + widx(1), p_off * k + widx(3));
    for i in 0..8 {
        sigma.swap((p_off + i) * k + widx(0), c_row * k + widx(24 + 2 * i));
        sigma.swap((p_off + i) * k + widx(1), c_row * k + widx(25 + 2 * i));
    }

    let wired = WiredExt::new(regions, wired_cols, sigma, Fp::from_u64(5), Fp::from_u64(7));
    let witness = wired.trace(&[ttrace, ctrace, ptrace]);
    let wproof = stark_prove_ext(&wired, &witness, 32, 8);
    assert!(
        stark_verify_ext(&wired, &wproof, 32, 8),
        "the transcript and compose regions were not consistently wired on the challenges"
    );
}

// Three regions in one proof: the transcript, the composition, and the DEEP check,
// with the composition value compose proved bound to the value DEEP consumes (and
// the challenges bound as before). So DEEP no longer trusts comp_z; it is the one
// compose proved was honestly formed from the frame.
#[test]
#[ignore]
fn the_transcript_compose_and_deep_are_wired_into_one_proof() {
    use crate::crypto::stark::air::{
        compose_inputs, AlphaPowers, deep_terms_query0, stark_prove_ext, stark_verify_ext, Air, AirExt,
        ComposeBoundary, ComposeCheck, DeepCheckExt, TranscriptCheck, WiredExt,
    };
    use crate::crypto::stark::field::Fp2;
    use crate::recursion_assembly::sponge::Recorder;
    use alloc::boxed::Box;

    let h = hasher();
    let (nq, grind, extra) = (32usize, 16u32, 3u32);
    let (air, proof) = poseidon_join_split_proof(&h, nq, grind, extra);
    let ci = compose_inputs(&air, &proof, extra, &h);
    let t = 1u64 << air.log_trace_len();
    let g = root_of_unity(air.log_trace_len());

    // Region 1: compose-at-z.
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
    let compose = ComposeCheck::new(
        window,
        periodic,
        coeffs,
        ci.z,
        ci.comp_z,
        g.pow(t - 1),
        t,
        boundaries,
    );
    let ctrace = compose.trace();

    // Region 2: the DEEP check, holding comp_z (its composition term claim) as a
    // wireable trace cell.
    let (terms, dx, ddeep) = deep_terms_query0(&air, &proof, extra, &h);
    let deepck = DeepCheckExt::new(terms, dx, ddeep);
    let dtrace = deepck.trace();

    // Region 0: transcript derivation, up to the out-of-domain point.
    let mut r = Recorder::new(&h);
    r.absorb_digest(&proof.trace_root);
    // The composition alpha, one operation; the coefficients are its powers
    // and ride their own region below.
    let (coeff_op, _) = r.challenge_fp2();
    r.absorb_digest(&proof.comp_root);
    let (z_op, _) = r.challenge_fp2();
    let transcript = TranscriptCheck::new(h.clone(), 2, r.finish());
    let ttrace = transcript.trace();

    // Region 3: the composition coefficients as powers of the squeezed alpha.
    let powers = AlphaPowers::new(ci.coeffs[1], ci.coeffs.len());
    let ptrace = powers.trace();
    let regions: Vec<Box<dyn AirExt>> = alloc::vec![
        Box::new(transcript) as Box<dyn AirExt>,
        Box::new(compose),
        Box::new(deepck),
        Box::new(powers),
    ];
    let l = 4usize;
    let t_height = 1usize << regions[0].log_trace_len();
    let c_off = t_height; // compose region offset
    let d_off = c_off + (1usize << regions[1].log_trace_len()); // DEEP region offset
    let p_off = d_off + (1usize << regions[2].log_trace_len());
    let span = (p_off + (1usize << regions[3].log_trace_len())).next_power_of_two();

    // wired columns: transcript squeeze lane (0), compose z+coeffs (22..39), compose
    // comp_z (54, 55), DEEP comp_z (4, 5).
    let mut wired_cols = alloc::vec![0usize, 1, 2, 3];
    for c in 22..40 {
        wired_cols.push(c);
    }
    wired_cols.push(54);
    wired_cols.push(55);
    wired_cols.push(4);
    wired_cols.push(5);
    let k = wired_cols.len();
    let widx = |col: usize| -> usize { wired_cols.iter().position(|&c| c == col).unwrap() };
    let mut sigma: Vec<usize> = (0..span * k).collect();
    // z and coefficients: transcript squeezes wire to compose columns.
    sigma.swap((z_op * l) * k, c_off * k + widx(22));
    sigma.swap((z_op * l) * k + widx(1), c_off * k + widx(23));
    sigma.swap((coeff_op * l) * k, p_off * k + widx(2));
    sigma.swap((coeff_op * l) * k + widx(1), p_off * k + widx(3));
    for i in 0..8 {
        sigma.swap((p_off + i) * k + widx(0), c_off * k + widx(24 + 2 * i));
        sigma.swap((p_off + i) * k + widx(1), c_off * k + widx(25 + 2 * i));
    }
    // comp_z: compose columns 54, 55 wire to DEEP columns 4, 5.
    sigma.swap(c_off * k + widx(54), d_off * k + widx(4));
    sigma.swap(c_off * k + widx(55), d_off * k + widx(5));

    let wired = WiredExt::new(regions, wired_cols, sigma, Fp::from_u64(5), Fp::from_u64(7));
    let witness = wired.trace(&[ttrace, ctrace, dtrace, ptrace]);
    let wproof = stark_prove_ext(&wired, &witness, 32, 8);
    assert!(
        stark_verify_ext(&wired, &wproof, 32, 8),
        "the transcript, compose, and DEEP regions were not consistently wired"
    );
}
