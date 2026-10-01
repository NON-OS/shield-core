// NONOS Operating System (AGPL-3.0-or-later)

use crate::crypto::stark::field::Fp;
use crate::crypto::stark::fri::root_of_unity;

extern crate alloc;
use alloc::vec::Vec;
#[allow(unused_imports)]
use super::{core::*, openings::*, compose::*, wired_a::*, codeword::*, wired_c::*};

// Five regions in one proof: the STARK transcript, composition, and DEEP (the
// computation half), plus the FRI transcript and the fold chain (the low-degree
// half), with the fold's challenges bound to the FRI transcript that squeezed them.
// So the fold no longer trusts its betas; they are the ones the FRI transcript
// proved.
#[test]
#[ignore]
fn the_full_verifier_computation_and_fold_are_wired_into_one_proof() {
    use crate::crypto::stark::air::{
        compose_inputs, AlphaPowers, deep_terms_query0, stark_prove_ext, stark_verify_ext, Air, AirExt,
        ComposeBoundary, ComposeCheck, DeepCheckExt, TraceFoldExt, TranscriptCheck, WiredExt,
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

    // Region 1: compose.
    let mut window = [Fp2::ZERO; 6];
    window.copy_from_slice(&proof.ood_frame[..6]);
    let mut cperiodic = [Fp2::ZERO; 5];
    cperiodic.copy_from_slice(&ci.periodic_z[..5]);
    let mut coeffs = [Fp2::ZERO; 8];
    coeffs.copy_from_slice(&ci.coeffs[..8]);
    let bnds: Vec<ComposeBoundary> = air
        .boundary()
        .iter()
        .map(|(col, row, e)| ComposeBoundary {
            col: *col,
            g_row: g.pow(*row as u64),
            expected: *e,
        })
        .collect();
    let compose = ComposeCheck::new(
        window,
        cperiodic,
        coeffs,
        ci.z,
        ci.comp_z,
        g.pow(t - 1),
        t,
        bnds,
    );
    let ctrace = compose.trace();

    // Region 2: DEEP.
    let (terms, dx, ddeep) = deep_terms_query0(&air, &proof, extra, &h);
    let deepck = DeepCheckExt::new(terms, dx, ddeep);
    let dtrace = deepck.trace();

    // Region 0: STARK transcript through z.
    let mut r = Recorder::new(&h);
    r.absorb_digest(&proof.trace_root);
    // The composition alpha, one operation; the coefficients are its powers
    // and ride their own region below.
    let (coeff_op, _) = r.challenge_fp2();
    r.absorb_digest(&proof.comp_root);
    let (z_op, _) = r.challenge_fp2();
    let transcript = TranscriptCheck::new(h.clone(), 2, r.finish());
    let ttrace = transcript.trace();

    // Region 3 + 4: the FRI transcript (interleaved absorb-root, squeeze-beta) and
    // the fold chain over the real proof's query 0.
    let fri = &proof.fri;
    let n_folds = fri.roots.len();
    let log_n = fri_log_n(&air, fri, extra);
    let n = 1usize << log_n;

    let mut fr = Recorder::new(&h);
    // FRI's transcript opens with the seed the STARK's transcript hands it,
    // absorbed before the first root, so its replay does too.
    let seed = crate::crypto::stark::air::replay::replay(&air, &proof, None, None, extra, &h, &[]).seed;
    fr.absorb(seed[0]);
    fr.absorb(seed[1]);
    let mut betas: Vec<Fp2> = Vec::with_capacity(n_folds);
    let mut beta_ops: Vec<usize> = Vec::with_capacity(n_folds);
    for root in &fri.roots {
        fr.absorb_digest(root);
        let (op, beta) = fr.challenge_fp2();
        beta_ops.push(op);
        betas.push(beta);
    }
    for value in &fri.final_layer {
        fr.absorb(value.c0);
        fr.absorb(value.c1);
    }
    assert!(fr.verify_pow(fri.pow_nonce, grind));
    let (_, _, q0) = fr.challenge_index(n);
    let fri_transcript = TranscriptCheck::new(h.clone(), 2, fr.finish());
    let fttrace = fri_transcript.trace();

    let final_value = fri_final_value(fri, log_n, q0);
    let base_omega = root_of_unity(log_n);
    let shift = Fp::from_u64(7);
    let layers = &fri.queries[0].layers;
    let (mut a, mut b, mut x_inv, mut dir) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for (m, op) in layers.iter().enumerate() {
        a.push(op.a);
        b.push(op.b);
        let half = n >> (m + 1);
        let i = q0 % half;
        let x = (shift * base_omega.pow(i as u64)).pow(1u64 << m);
        x_inv.push(x.inv());
        dir.push(i >= (n >> (m + 2)));
    }
    a.push(final_value);
    b.push(final_value);
    let log_layers = (n_folds + 1).next_power_of_two().trailing_zeros();
    let fold = TraceFoldExt::new(log_layers, n_folds, x_inv, dir, final_value);
    let ftrace = fold.trace(&betas, &a, &b);

    // Region 5: the composition coefficients as powers of the squeezed alpha.
    let powers = AlphaPowers::new(ci.coeffs[1], ci.coeffs.len());
    let ptrace = powers.trace();
    let regions: Vec<Box<dyn AirExt>> = alloc::vec![
        Box::new(transcript) as Box<dyn AirExt>,
        Box::new(compose),
        Box::new(deepck),
        Box::new(fri_transcript),
        Box::new(fold),
        Box::new(powers),
    ];
    let l = 4usize;
    // Regions stack by the rows they occupy, not their padded traces: the
    // stack's own rule (`fusion::region_offsets`), or every index into a
    // region that does not fill its trace lands on the wrong row.
    let off: Vec<usize> = {
        let mut v = Vec::new();
        let mut r = 0usize;
        for reg in &regions {
            v.push(r);
            r += reg.rows();
        }
        v
    };
    let span = {
        let mut r = 0usize;
        for reg in &regions {
            r += reg.rows();
        }
        r.next_power_of_two()
    };
    let (c_off, d_off, ft_off, f_off, p_off) = (off[1], off[2], off[3], off[4], off[5]);

    // wired columns: transcript squeeze lane (0), compose z+coeffs (22..39), compose
    // and DEEP comp_z (54,55 and 4,5), and the fold beta cells (columns 0,1 of the
    // fold region, but the fold shares low columns 0,1 with the transcript squeeze
    // lane 0, so beta.c1 uses column 1).
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
    // z and coefficients.
    sigma.swap((z_op * l) * k + widx(0), c_off * k + widx(22));
    sigma.swap((z_op * l) * k + widx(1), c_off * k + widx(23));
    sigma.swap((coeff_op * l) * k + widx(0), p_off * k + widx(2));
    sigma.swap((coeff_op * l) * k + widx(1), p_off * k + widx(3));
    for i in 0..8 {
        sigma.swap((p_off + i) * k + widx(0), c_off * k + widx(24 + 2 * i));
        sigma.swap((p_off + i) * k + widx(1), c_off * k + widx(25 + 2 * i));
    }
    // comp_z.
    sigma.swap(c_off * k + widx(54), d_off * k + widx(4));
    sigma.swap(c_off * k + widx(55), d_off * k + widx(5));
    // betas: the two lanes of the FRI transcript operation that read beta m
    // wire to the fold's beta cells (row m, columns 0 and 1).
    for (m, op) in beta_ops.iter().enumerate().take(n_folds) {
        let b_row = ft_off + op * l;
        sigma.swap(b_row * k + widx(0), (f_off + m) * k + widx(0));
        sigma.swap(b_row * k + widx(1), (f_off + m) * k + widx(1));
    }

    let wired = WiredExt::new(regions, wired_cols, sigma, Fp::from_u64(5), Fp::from_u64(7));
    let witness = wired.trace(&[ttrace, ctrace, dtrace, fttrace, ftrace, ptrace]);
    let wproof = stark_prove_ext(&wired, &witness, 32, 8);
    assert!(
        stark_verify_ext(&wired, &wproof, 32, 8),
        "the five verifier regions were not consistently wired"
    );
}

// All six regions in one proof: the STARK transcript, composition, and DEEP; the
// FRI transcript and fold; and the Merkle authentication that binds the fold's
// opened value to the committed FRI codeword root. This is the whole verifier of a
// real Poseidon-committed proof, arithmetized and wired into one statement, with
// every challenge proven squeezed and every opened value authenticated.
