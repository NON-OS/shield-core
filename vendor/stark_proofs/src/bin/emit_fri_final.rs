// NONOS Operating System (AGPL-3.0-or-later)
//! The FRI final polynomial of a settlement proof, and its value at every
//! query's final point: the vector a verifier holds its early-stop branch
//! against.
//!
//!     emit_fri_final <settlement.proof> <out.json>
//!
//! The proof is a two round keccak artifact as `emit_recursion_pre` writes
//! it, with its `.publics.json` beside it. The domain comes from the
//! settlement outer assembled here, never from the artifact, and the query
//! indices are replayed from the proof's own transcript the way the verifier
//! replays them: the STARK transcript up to its seed, then FRI's under it. Coefficients are the
//! final polynomial's, lowest degree first; `x_final` is the query's point
//! after every fold; `value` is the polynomial there, which the last fold
//! of that query lands on.

use stark_proofs::crypto::stark::air::replay_pre::replay_comp_z_pre;
use stark_proofs::crypto::stark::air::{domain_params_blown, Air};
use stark_proofs::crypto::stark::field::Fp;
use stark_proofs::crypto::stark::fri::{n_folds, stop_log};
use stark_proofs::crypto::stark::fri_ext::fri_final_vector_ext;
use stark_proofs::host::{die, read_text, Json};
use stark_proofs::proof_wire::{deserialize_rounds, ParamSet};
use stark_proofs::recursion_assembly::point::Point;
use stark_proofs::shield_params::inner as inner_point;

fn f2(v: &stark_proofs::crypto::stark::field::Fp2) -> String {
    format!("[{}, {}]", v.c0.to_u64(), v.c1.to_u64())
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let [proof_path, out] = [a.first(), a.get(1)].map(|x| {
        x.cloned()
            .unwrap_or_else(|| die("usage: emit_fri_final <settlement.proof> <out.json>"))
    });
    let raw = std::fs::read(&proof_path)
        .unwrap_or_else(|e| die(&format!("cannot read {proof_path}: {e}")));
    let publics: Vec<Fp> = Json(&read_text(&format!("{proof_path}.publics.json")))
        .u64s("publics")
        .into_iter()
        .map(Fp::from_u64)
        .collect();

    let mut asm = Point::Settlement
        .assemble_wired(Point::emit_wiring())
        .unwrap_or_else(|why| die(&why));
    let params = ParamSet::of(
        &asm.wired,
        inner_point::N_QUERIES,
        inner_point::GRIND_BITS,
        inner_point::EXTRA_BLOWUP_BITS,
    );
    let rounds = deserialize_rounds(&raw, &params).unwrap_or_else(|| {
        die("the artifact does not parse as a two round proof at the deployment point")
    });
    let seed = replay_comp_z_pre(
        &mut asm.wired,
        &rounds.pre,
        Some(&rounds.perm_root),
        inner_point::EXTRA_BLOWUP_BITS,
        &publics,
    )
    .unwrap_or_else(|why| panic!("the proof does not replay: {why}"))
    .seed;
    let proof = &rounds.pre.proof;
    let (log_n, log_blowup) = domain_params_blown(&asm.wired, inner_point::EXTRA_BLOWUP_BITS);
    let k = stop_log(log_n, log_blowup);
    let folds = n_folds(log_n, log_blowup);
    if proof.fri.roots.len() != folds || proof.fri.final_layer.len() != 1usize << k {
        die(&format!(
            "the artifact has {} folds and {} final coefficients; the settlement outer at this schedule has {folds} and {}",
            proof.fri.roots.len(),
            proof.fri.final_layer.len(),
            1usize << k
        ));
    }
    let shift = Fp::from_u64(stark_proofs::crypto::stark::air::COSET_SHIFT);
    let vector = fri_final_vector_ext(
        &proof.fri,
        shift,
        log_n,
        log_blowup,
        inner_point::GRIND_BITS,
        Some(&seed),
    );
    if vector.is_empty() {
        die("the proof-of-work did not check; the artifact is not a proof at this point");
    }
    let coeffs: Vec<String> = proof.fri.final_layer.iter().map(f2).collect();
    let queries: Vec<String> = vector
        .iter()
        .map(|(q, x, v)| {
            format!(
                "    {{\"q\": {q}, \"x_final\": {}, \"value\": {}}}",
                f2(x),
                f2(v)
            )
        })
        .collect();
    let json = format!(
        "{{\n  \"artifact\": \"{proof_path}\",\n  \"log_n\": {log_n},\n  \"log_blowup\": {log_blowup},\n  \"stop_log\": {k},\n  \"n_folds\": {folds},\n  \"last_check\": \"folded == sum_j coefficients[j] * x_final^j\",\n  \"x_final\": \"(shift * omega^(q mod (n >> n_folds)))^(2^n_folds), shift {}, omega the 2^log_n root of unity\",\n  \"coefficients\": [{}],\n  \"queries\": [\n{}\n  ]\n}}\n",
        stark_proofs::crypto::stark::air::COSET_SHIFT,
        coeffs.join(", "),
        queries.join(",\n")
    );
    std::fs::write(&out, json).unwrap_or_else(|e| die(&format!("cannot write {out}: {e}")));
    println!(
        "wrote {} coefficients and {} queries to {out} ({} rows, {} folds, k {k})",
        coeffs.len(),
        vector.len(),
        1usize << Air::log_trace_len(&asm.wired),
        folds
    );
}
