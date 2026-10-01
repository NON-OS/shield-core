// NONOS Operating System (AGPL-3.0-or-later)
//! The region layout, for a verifier whose evaluators are config-driven over
//! it: every Layout scalar, the region bases, and the permutation's committed
//! geometry. Same discipline as the shape file: derived, gated by the
//! satisfaction walk the caller ran, never typed.

use stark_proofs::crypto::stark::air::Air;
use stark_proofs::recursion_assembly::build::Assembly;
use stark_proofs::recursion_assembly::point::Point;
use stark_proofs::shield_params::inner as inner_point;
use std::time::Instant;

/// `args` carries the root cache flags, `out` the shape file's path, and
/// `json` the shape itself, whose digest keys the cached periodic root.
pub fn emit(asm: &Assembly, at: &Point, args: &[String], out: &str, json: &str) {
    let extra_blowup_bits = inner_point::EXTRA_BLOWUP_BITS;
    let num_transition = asm.wired.num_transition();
    let lay = &asm.lay;
    // The outer's periodic root is the one allocation here that scales with the
    // outer, so it is computed first and announced on both sides.
    /*
     * At the point's own rate, not at rate one half.
     *
     * This read `periodic_root(&asm.wired, 0)`. The periodic tree commits the
     * coset extension of the periodic columns, and that extension's domain is
     * the rate's, so a root taken at extra blowup zero and one taken at three
     * are different trees over domains eight times apart. The prover and the
     * verifier both use the point's own value, so the constant this file
     * published was the one no settlement proof could ever open against, and a
     * contract that baked it would have refused every proof it was handed.
     *
     * The rate is in the field name now as well, because this is one more
     * value whose name did not say which instance of a quantity it was.
     */
    /*
     * Content addressed against the structure file just written, which is the
     * complete statement of everything this root depends on: it carries
     * `periodic_root_poseidon`, a commitment to the periodic columns
     * themselves, alongside the domain, the rate and the coset shift. So the
     * key moves exactly when the tree would, and a miss is what says the root
     * is stale rather than somebody remembering that it might be.
     *
     * This matters because the commitment is 97 to 99 per cent of the run,
     * 3 h 35 m at settlement and 9 h 21 m at e64, against about three minutes
     * for every other field in both files together. Republishing a metadata
     * field used to cost most of a day of Keccak to reprint a number that had
     * not moved.
     *
     * `root=<hex>` supplies a root already computed elsewhere and stores it
     * under this key, which is how the two roots that already exist are seeded
     * without paying for them twice. `force-root` recomputes and overwrites.
     */
    let cache_dir = stark_proofs::root_cache::cache_dir(out);
    let key = stark_proofs::root_cache::digest(json.as_bytes());
    let supplied = args.iter().find_map(|a| a.strip_prefix("root="));
    let forced = args.iter().any(|a| a == "force-root");

    let cached = if forced {
        None
    } else {
        stark_proofs::root_cache::get(&cache_dir, &key)
    };

    let outer_root_hex: String = match (supplied, cached) {
        (Some(hex), _) => {
            eprintln!("periodic root supplied, storing under {key}");
            hex.trim().to_ascii_lowercase()
        }
        (None, Some(hit)) => {
            eprintln!("periodic root from cache, key {key}");
            hit
        }
        (None, None) => {
            eprintln!("computing the outer periodic root at extra blowup {extra_blowup_bits}");
            let t = Instant::now();
            let r = stark_proofs::crypto::stark::air::periodic_root(&asm.wired, extra_blowup_bits);
            eprintln!("outer periodic root computed in {:?}", t.elapsed());
            r[..stark_proofs::crypto::stark::merkle::DIGEST_BYTES].iter().map(|b| format!("{b:02x}")).collect()
        }
    };
    if let Err(e) = stark_proofs::root_cache::put(&cache_dir, &key, &outer_root_hex) {
        eprintln!("could not store the periodic root: {e}");
    }
    /*
     * The outer's own periodic columns: what a query's periodic row carries,
     * and what the chain opens against the keccak root above. This is not
     * n_pz. That one counts the inner's periodic columns, which the recursion
     * checks in circuit against the Poseidon root in the shape. Two
     * commitments over two column sets, under two hashes, and reading one for
     * the other fails every opening, so both are emitted side by side.
     */
    let outer_n_periodic = asm.wired.periodic_columns().len();
    eprintln!("outer periodic root done, {outer_n_periodic} outer periodic columns");
    /*
     * The kind map: which constraint body each kind runs, where its periodic
     * values begin, and how wide its body is. This is the one thing about the
     * outer that a verifier cannot derive from any other emitted number, because
     * it is a statement about how the assembler pushed its regions rather than a
     * property of the trace.
     */
    let kmap = asm.wired.kind_map();
    /*
     * The widest arity among the kinds that are not compose. The widest arity
     * overall is already `group_constraint_base` under another name, because
     * the fused AIR takes the maximum arity as its region lane count and then
     * appends one lane per group, so emitting it again would be the same
     * subtraction twice with two names. What is not derivable is where compose
     * stops being the only contributor: every kind contributes at every index
     * below its own arity, so a verifier that dispatches per lane needs to know
     * how far up the vector a second body can still reach. Compose is named
     * rather than inferred from the width, because a body being widest is a
     * fact about this circuit and not a definition.
     */
    let max_noncompose_arity = kmap
        .iter()
        .zip(&asm.kind_bodies)
        .filter(|(_, (body, _))| *body != "compose")
        .map(|(&(_, _, arity, _, _), _)| arity)
        .max()
        .unwrap_or(0);
    assert_eq!(
        kmap.len(),
        asm.kind_bodies.len(),
        "every kind must name the body it runs"
    );
    let kinds_json: Vec<String> = kmap
        .iter()
        .zip(&asm.kind_bodies)
        .enumerate()
        .map(
            |(k, (&(base, slots, arity, instances, width), (body, role)))| {
                format!(
                    "{{\"kind\": {k}, \"body\": \"{body}\", \"role\": \"{role}\", \
                 \"periodic_base\": {base}, \"slots\": {slots}, \"arity\": {arity}, \
                 \"instances\": {instances}, \"region_width\": {width}}}"
                )
            },
        )
        .collect();
    /*
     * A kind that owns no periodic columns leaves the next kind starting at the
     * same base, so the base list is not injective and cannot identify a kind at
     * all. Counted here rather than left as a remark, so a reader who wants to
     * know whether the property still holds can read a number instead of
     * rediscovering it.
     */
    let base_collisions = kmap
        .iter()
        .enumerate()
        .filter(|(i, &(base, _, _, _, _))| {
            kmap.iter()
                .take(*i)
                .any(|&(other, _, _, _, _)| other == base)
        })
        .count();
    eprintln!("reading the permutation columns");
    let (sel_idx, row_idx, sig_base) = asm.wired.permutation_columns();
    eprintln!(
        "permutation columns read; formatting {} groups",
        sig_base.len()
    );
    /*
     * The challenges are the proof's, not the circuit's, and this file must not
     * publish a number for them.
     *
     * This binary assembles and never proves, so the pair in the groups is the
     * assembled default, 5 and 7, which is the pair the recorded forgery was
     * built at. The prover overwrites it between committing the region columns
     * and building the permutation columns, and the verifier overwrites it from
     * the same transcript. Emitting the default as `"beta": 5` published a
     * circuit constant for a quantity the transcript determines, and a verifier
     * generated from that field would bake the forgery's own pair.
     *
     * So the field is null while the pair is undrawn, and the emit refuses
     * outright if it ever finds them drawn here, because a number in this file
     * is only correct for one proof and this file describes all of them.
     */
    assert_eq!(
        asm.wired.n_challenges(),
        0,
        "the assembly has drawn its challenges; a layout cannot publish a pair \
         that belongs to one proof"
    );
    let groups_json: Vec<String> = asm
        .wired
        .group_params()
        .iter()
        .zip(&sig_base)
        .map(|((cols, _beta, _gamma), sb)| {
            format!(
                "{{\"wired_cols\": {:?}, \"beta\": null, \"gamma\": null, \
                 \"challenge_source\": \"transcript after trace_root\", \
                 \"sigma_base_col\": {}}}",
                cols, sb
            )
        })
        .collect();
    let layout = format!(
        "{{\n  \"n_inners\": {},\n  \"digest_bytes\": {},\n  \"final_layer_coefficients\": {},\n  \
         \"inner_extra_blowup_bits\": {},\n  \
         \"inner_soundness_bits\": {},\n  \"span\": {},\n  \"l\": {},\n  \"n_q\": {},\n  \
         \"region_offsets\": {:?},\n  \
         \"z_op\": {},\n  \"coeff_op\": {},\n  \"deep_coeff_op\": {},\n  \
         \"rounds\": {},\n  \"beta_op\": {},\n  \"ra_depth\": {},\n  \"n_chal\": {},\n  \
         \"c_chal_col\": {},\n  \"pub_len\": {},\n  \
         \"coeff_powers_off\": {},\n  \
         \"deep_powers_off\": {},\n  \"draw_value_row\": {},\n  \"horner_value_row\": {},\n  \
         \"n_final\": {},\n  \"n_terms\": {},\n  \"width_inner\": {},\n  \
         \"window_inner\": {},\n  \"depth\": {},\n  \"n_open\": {},\n  \"n_folds\": {},\n  \
         \"log_n_inner\": {},\n  \"inner_log_fri_domain\": {},\n  \
         \"inner_fold_layers\": {},\n  \
         \"pbits\": {},\n  \"fbits\": {},\n  \"t_inner\": {},\n  \
         \"n_pz\": {},\n  \"pa_depth\": {},\n  \"n_pz_absorb_chunks\": {},\n  \"frame_len\": {},\n  \
         \"n_coeff\": {},\n  \"c_periodic_col\": {},\n  \"c_z_col\": {},\n  \"c_coeff_col\": {},\n  \
         \"c_comp_z_col\": {},\n  \"sel_col\": {},\n  \"row_col\": {},\n  \
         \"strip_off\": {},\n  \"strip_k\": {},\n  \"strip_echo_width\": {},\n  \
         \"strip_n_out_lanes\": {},\n  \"strip_rows\": {},\n  \
         \"compose_mode\": \"{}\",\n  \"compose_out_pin\": \"{}\",\n  \
         \"compose_acc_base_col\": {},\n  \"compose_acc_base_slot\": {},\n  \
         \"outer_n_periodic\": {},\n  \
         \"n_deep_terms\": {},\n  \
         \"outer_periodic_root_keccak_at_deployment_rate\": \"{}\",\n  \
         \"max_noncompose_arity\": {},\n  \"periodic_base_collisions\": {},\n  \
         \"product_columns\": {},\n  \
         \"group_column_base\": {},\n  \
         \"group_constraint_base\": {},\n  \
         \"kinds\": [\n    {}\n  ],\n  \
         \"groups\": [\n    {}\n  ]\n}}\n",
        at.inners(),
        stark_proofs::crypto::stark::merkle::DIGEST_BYTES,
        1usize << stark_proofs::crypto::stark::fri::FRI_STOP_LOG,
        at.inner_extra(),
        at.inner_queries() * (1 + at.inner_extra() as usize) + inner_point::GRIND_BITS as usize,
        lay.span,
        lay.l,
        lay.n_q,
        asm.region_offsets,
        lay.z_op,
        lay.coeff_op,
        lay.deep_coeff_op,
        lay.rounds,
        lay.beta_op,
        lay.ra_depth,
        lay.n_chal,
        lay.c_chal_col,
        lay.pub_len,
        lay.cp_off,
        lay.dp_off,
        lay.draw_value_row,
        lay.horner_value_row,
        lay.n_final,
        lay.n_terms,
        lay.width_inner,
        lay.window_inner,
        lay.depth,
        lay.n_open,
        lay.n_folds,
        /*
         * Three names for two quantities, until the old one goes. `log_n_inner`
         * is the log of the inner's FRI evaluation domain, the height of the
         * fold tower, and it is emitted again as `inner_log_fri_domain` because
         * the old name reads as a sibling of `inner_log_trace_len` and is not
         * one: the trace is 13 where the domain is 21. The layer count is
         * emitted beside it so the pair cannot be mistaken for one number. The
         * old key stays for one release, then goes.
         */
        lay.log_n,
        lay.log_n,
        lay.n_folds,
        lay.pbits,
        lay.fbits,
        lay.t_inner,
        lay.n_pz,
        lay.pa_depth,
        lay.n_pz_absorb_chunks,
        lay.frame_len,
        lay.n_coeff,
        lay.c_periodic_col,
        lay.c_z_col,
        lay.c_coeff_col,
        lay.c_comp_z_col,
        sel_idx,
        row_idx,
        lay.strip_off,
        lay.strip_k,
        lay.strip_echo_width,
        lay.strip_n_out,
        lay.strip_rows,
        /*
         * The branch the compose region takes, published rather than left to be
         * inferred. Everything needed to infer it wrongly was already emitted:
         * `strip_n_out_lanes` is present on both paths and reads as a count of
         * inner transitions, so a consumer can implement the in-region
         * recompute, get plausible values, and disagree only on the out pins.
         * The pin itself is carried as a string because the arithmetic, not the
         * mode name, is what a consumer has to reproduce.
         */
        if lay.strip_n_out == 0 { "flat" } else { "strip" },
        if lay.strip_n_out == 0 {
            "out[i] - transition_gen(frame, periodic)[i]"
        } else {
            "out[i] - acc[i] - stmt[i]"
        },
        lay.compose_acc_base_col,
        lay.compose_acc_base_col / 2,
        outer_n_periodic,
        // Two rows of the opened frame, a claim per periodic column at z, and
        // the composition value. Distinct from `n_coeffs`, which counts the
        // composition's own batching and is a different size of a different
        // thing.
        2 * asm.wired.trace_width() + outer_n_periodic + 1,
        outer_root_hex,
        max_noncompose_arity,
        base_collisions,
        /*
         * Two bases with the same arithmetic shape over different vectors, so
         * both are named rather than left to be inferred. The column base is
         * where the running product columns begin in the trace; the constraint
         * base is where their lanes begin in the constraint vector. Reading one
         * where the other was meant lands in the wrong vector entirely, which
         * is why they are emitted apart.
         *
         * Both subtract the number of product columns, and that is not the
         * number of groups. The packed form keeps one column per group, so the
         * two agreed and this read `- asm.n_groups`. The chained form keeps one
         * per accumulator step: the settlement outer has one group over 458
         * wired columns and 58 steps, so both bases were emitted 57 too high.
         * A consumer indexing 58 group lanes from 247 reads 57 region lanes and
         * runs off the end of the vector.
         */
        /*
         * Emitted beside the two bases it is subtracted from, so a consumer can
         * check the subtraction instead of trusting it. The relation gate in
         * ci/emit_agree.py evaluates
         * `group_constraint_base + product_columns == num_transition`, which is
         * the identity the 57 too high bases broke while every field in the
         * directory still read as a plausible number on its own.
         */
        asm.wired.product_columns(),
        asm.wired.trace_width() - asm.wired.product_columns(),
        num_transition - asm.wired.product_columns(),
        kinds_json.join(",\n    "),
        groups_json.join(",\n    "),
    );
    let lay_out = out.replace(".json", "-layout.json");
    eprintln!(
        "layout formatted, {} bytes; writing {lay_out}",
        layout.len()
    );
    std::fs::write(&lay_out, &layout).expect("write layout");
    println!("wrote {lay_out}");
}
