// NONOS Operating System (AGPL-3.0-or-later)
//! The program-form outer's composition at z, term by term, for a verifier
//! that recomputes it.
//!
//! A chain verifier that computes comp_z from the frame instead of being told
//! it evaluates every transition constraint and every boundary at z and sums
//! them under the drawn coefficients. Checked only against the final sum, a
//! wrong term is one wrong number among hundreds. This prints each one:
//!
//!     transitions   index, C_i(z), alpha_i, and the term alpha_i C_i(z) E(z) / Z_H(z)
//!     boundaries    index, column, row, the value and where it comes from,
//!                   alpha, 1 / (z - g^row), and the term
//!
//! where E(z) is the product of (z - g^(t - k)) over the exempt rows. A
//! boundary's source is `const` when the value is the circuit's, or `public k`
//! when it is the statement's word k: those values a verifier reads from the
//! calldata publics, never from this file. The sum is checked against the
//! comp_z the verifier's own replay derives before anything is written.
//!
//!     emit_program_oracle <proof> <out.json> [point=settlement]
//!     emit_program_oracle <proof> <out.json> inner=<in.inner> intent=<in.intent.json> [point=settlement]
//!
//!     emit_program_oracle <proof> <out.json> direct q=<n> grind=<g> extra=<e>
//!     emit_program_oracle <proof> <out.json> attest q=<n> grind=<g> extra=<e>
//!
//! Without `inner=` the outer is the release fixture's. With `direct` the
//! circuit is the join-split itself, proved for the chain with no outer
//! (`measure_direct`), rebuilt from the proof's words. The publics are the
//! proof's own `<proof>.publics.json`.

use stark_proofs::crypto::stark::air::replay_pre::replay_comp_z_pre;
use stark_proofs::crypto::stark::air::{
    periodic_root_poseidon, stark_verify_poseidon_rounds, Air, AirExt, Poseidon, WiredMultiExt,
};
use stark_proofs::crypto::stark::field::{Fp, Fp2};
use stark_proofs::crypto::stark::fri::root_of_unity;
use stark_proofs::host::{die, point_from_args, read_text, Json};
use stark_proofs::proof_wire::{deserialize_p_rounds, deserialize_rounds, ParamSet};
use stark_proofs::recursion_assembly::anchors::Anchors;
use stark_proofs::recursion_assembly::inner::{
    self, hasher, pack_air, shield_join_split, GRIND, NQ,
};
use stark_proofs::recursion_assembly::point::Point;
use stark_proofs::recursion_assembly::{assemble_over_gen_form, ComposeForm, Tamper};
use stark_proofs::shield::join::join_split_shape;
use stark_proofs::shield::member::TREE_DEPTH;
use std::fmt::Write as _;

fn e(v: Fp2) -> String {
    format!("[{}, {}]", v.c0.to_u64(), v.c1.to_u64())
}

/// The outer over the inner named on the command line, or the fixture's.
fn outer(h: &Poseidon, a: &[String]) -> (WiredMultiExt, Vec<Fp>) {
    let inner_path = a.iter().find_map(|s| s.strip_prefix("inner="));
    let intent_path = a.iter().find_map(|s| s.strip_prefix("intent="));
    let packed = match (inner_path, intent_path) {
        (None, None) => shield_join_split(h),
        (Some(ip), Some(tp)) => {
            let intent: Vec<Fp> = Json(&read_text(tp))
                .u64s("publics")
                .into_iter()
                .map(Fp::from_u64)
                .collect();
            let bytes =
                std::fs::read(ip).unwrap_or_else(|e| die(&format!("cannot read {ip}: {e}")));
            let proof =
                deserialize_p_rounds(&bytes).unwrap_or_else(|| die(&format!("{ip}: not an inner")));
            let mut shape = join_split_shape(TREE_DEPTH, &intent);
            let root = periodic_root_poseidon(&shape, inner::extra(), h);
            if !stark_verify_poseidon_rounds(
                &mut shape,
                &proof,
                NQ,
                GRIND,
                inner::extra(),
                h,
                &intent,
                &root,
            ) {
                die("the inner does not verify against its intent");
            }
            pack_air(h, shape, proof, intent, root, inner::extra(), GRIND)
        }
        _ => die("inner= and intent= go together"),
    };
    let outer = assemble_over_gen_form(
        h,
        packed,
        Tamper::None,
        usize::MAX,
        Point::emit_wiring(),
        Anchors::Collapsed,
        ComposeForm::Program,
    );
    (outer.gen.into_wired(), outer.publics)
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (Some(proof_path), Some(out)) = (a.first(), a.get(1)) else {
        die("usage: emit_program_oracle <proof> <out.json> [inner=<f> intent=<f>] [point=settlement]")
    };
    let attest = a.iter().any(|s| s == "attest");
    let direct = attest || a.iter().any(|s| s == "direct");
    let publics: Vec<Fp> = Json(&read_text(&format!("{proof_path}.publics.json")))
        .u64s("publics")
        .into_iter()
        .map(Fp::from_u64)
        .collect();
    let num = |key: &str| -> u64 {
        a.iter()
            .find_map(|s| s.strip_prefix(key))
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| die(&format!("direct takes {key}<n>")))
    };
    let (n_queries, grind_bits, extra_blowup) = if direct {
        (
            num("q=") as usize,
            num("grind=") as u32,
            num("extra=") as u32,
        )
    } else {
        point_from_args(&a)
    };
    let h = hasher();
    let (mut air, assembled) = if attest {
        (
            stark_proofs::attest::shape(&publics)
                .unwrap_or_else(|| die("the publics are not an attestation statement's nine words"))
                .into_wired(),
            publics.clone(),
        )
    } else if direct {
        (
            join_split_shape(TREE_DEPTH, &publics).into_wired(),
            publics.clone(),
        )
    } else {
        outer(&h, &a)
    };
    if publics != assembled {
        die("the proof's publics are not the statement this outer was assembled over");
    }
    if !air.bind_public_pins(&publics) {
        die("the publics do not fit the circuit's public pins");
    }

    let params = ParamSet::of(&air, n_queries, grind_bits, extra_blowup);
    let bytes = std::fs::read(proof_path)
        .unwrap_or_else(|e| die(&format!("cannot read {proof_path}: {e}")));
    let rounds = deserialize_rounds(&bytes, &params).unwrap_or_else(|| {
        die(&format!(
            "{proof_path}: not a proof at this point for this circuit"
        ))
    });
    let replay = replay_comp_z_pre(
        &mut air,
        &rounds.pre,
        Some(&rounds.perm_root),
        extra_blowup,
        &publics,
    )
    .unwrap_or_else(|why| die(why));
    // Beta then gamma, their components when the circuit argues in `Fp2`.
    let (beta, gamma) = replay
        .challenges
        .unwrap_or_else(|| die("a two round proof draws its challenges"));
    // `[[b0, b1], [g0, g1]]` in `Fp2`, `[b, g]` in `Fp`: the shape the chain's port reads.
    let chal: Vec<String> = if air.ext_challenges() {
        [beta, gamma]
            .iter()
            .map(|v| format!("[{}, {}]", v.c0.to_u64(), v.c1.to_u64()))
            .collect()
    } else {
        [beta.c0, gamma.c0]
            .iter()
            .map(|v| v.to_u64().to_string())
            .collect()
    };

    let z = replay.z;
    let log_t = air.log_trace_len();
    let t = 1u64 << log_t;
    let g = root_of_unity(log_t);
    let frame = &rounds.pre.proof.ood_frame;
    let periodic = &rounds.pre.periodic_z;
    let coeffs = &replay.coeffs;

    let z_h_inv = (z.pow(t) - Fp2::ONE).inv();
    let exempt_rows: Vec<u64> = (1..air.window_size() as u64).map(|k| t - k).collect();
    let mut exempt = Fp2::ONE;
    for &r in &exempt_rows {
        exempt = exempt * (z - Fp2::from_base(g.pow(r)));
    }

    let transition = air.transition_ext(frame, periodic);
    let boundary = Air::boundary(&air);
    let n_tr = transition.len();
    if coeffs.len() != n_tr + boundary.len() {
        die("the coefficient count is not transitions plus boundaries");
    }
    let n_pub = air.public_pins();
    let pins = air.public_pin_range();
    let pub_from = pins.start;
    for (k, j) in pins.clone().enumerate() {
        if boundary[j].2 != publics[k] {
            die(&format!(
                "boundary {j} is not public word {k}; the pin range is wrong"
            ));
        }
    }

    let mut sum = Fp2::ZERO;
    let mut tr = String::new();
    for (i, (c, alpha)) in transition.iter().zip(coeffs.iter()).enumerate() {
        let term = *alpha * (*c * exempt * z_h_inv);
        sum = sum + term;
        let sep = if i == 0 { "" } else { ",\n" };
        let _ = write!(
            tr,
            "{sep}    {{\"i\": {i}, \"c\": {}, \"alpha\": {}, \"term\": {}}}",
            e(*c),
            e(*alpha),
            e(term)
        );
    }
    let mut bd = String::new();
    for (j, (&(col, row, value), alpha)) in boundary.iter().zip(coeffs[n_tr..].iter()).enumerate() {
        let inv = (z - Fp2::from_base(g.pow(row as u64))).inv();
        let term = *alpha * ((frame[col] - Fp2::from_base(value)) * inv);
        sum = sum + term;
        let source = if pins.contains(&j) {
            format!("public {}", j - pub_from)
        } else {
            "const".to_string()
        };
        let sep = if j == 0 { "" } else { ",\n" };
        let _ = write!(
            bd,
            "{sep}    {{\"i\": {}, \"col\": {col}, \"row\": {row}, \"value\": {}, \"source\": \"{source}\", \
             \"alpha\": {}, \"inv\": {}, \"term\": {}}}",
            n_tr + j,
            value.to_u64(),
            e(*alpha),
            e(inv),
            e(term)
        );
    }
    println!("comp_z    summed {} replayed {}", e(sum), e(replay.comp_z));
    if sum != replay.comp_z {
        die("the terms do not sum to the verifier's comp_z; nothing written");
    }

    let frame_s: Vec<String> = frame.iter().map(|v| e(*v)).collect();
    let periodic_s: Vec<String> = periodic.iter().map(|v| e(*v)).collect();
    let publics_s: Vec<String> = publics.iter().map(|v| v.to_u64().to_string()).collect();
    let exempt_s: Vec<String> = exempt_rows.iter().map(|r| r.to_string()).collect();
    let json = format!(
        "{{\n  \"artifact\": \"{proof_path}\",\n  \"form\": \"program\",\n  \
         \"log_trace_len\": {log_t},\n  \"g\": {},\n  \"width\": {},\n  \"window\": {},\n  \
         \"n_transition\": {n_tr},\n  \"n_boundary\": {},\n  \"n_public_pins\": {n_pub},\n  \
         \"public_pins_from\": {},\n  \"challenges\": [{}],\n  \"z\": {},\n  \
         \"exempt_rows\": [{}],\n  \"exempt_at_z\": {},\n  \"z_h_inv\": {},\n  \
         \"publics\": [{}],\n  \"frame\": [{}],\n  \"periodic_z\": [{}],\n  \
         \"transitions\": [\n{tr}\n  ],\n  \"boundaries\": [\n{bd}\n  ],\n  \"comp_z\": {}\n}}\n",
        g.to_u64(),
        air.trace_width(),
        air.window_size(),
        boundary.len(),
        n_tr + pub_from,
        chal.join(", "),
        e(z),
        exempt_s.join(", "),
        e(exempt),
        e(z_h_inv),
        publics_s.join(", "),
        frame_s.join(", "),
        periodic_s.join(", "),
        e(sum)
    );
    std::fs::write(out, json).unwrap_or_else(|e| die(&format!("cannot write {out}: {e}")));
    println!(
        "wrote {out}: {n_tr} transitions, {} boundaries of which {n_pub} read from the publics",
        boundary.len()
    );
}
