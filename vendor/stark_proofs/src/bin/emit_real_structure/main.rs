// NONOS Operating System (AGPL-3.0-or-later)
//! The real outer's shape, from the full query assembly: the structure a
//! settlement verifier derives its constants from, the baked periodic root it
//! holds, and a satisfaction walk over the whole witness so the shape shipped is
//! a shape that provably accepts. No proving here; the proof artifact is the
//! emitter's job. This is the contract side's re-gate input for the real
//! circuit, produced whole or not at all.
//!
//! By default the outer is assembled over the settlement inner, 32 queries at
//! rate 1/16, the point the registered keys hold. With `transfer` it is assembled
//! over a transfer inner at rate 1/4, 56 queries unless `queries=N` says
//! otherwise, which is what the outer would have to verify if senders proved at
//! that point. Run at 56 and at 64 and the emitted layout, rather than an
//! estimate, says what adopting the transfer point costs the recursion and
//! whether the 144 bit count still fits the same trace budget: the outer's span
//! and log trace length are the numbers to read.
//!
//! The outer's authentication regions size the inner's evaluation domain from
//! `inner::extra()`, which the environment sets. A transfer assembly is therefore
//! only consistent under `NONOS_INNER_EXTRA=1`, and the emit refuses to run the
//! transfer mode under any other value rather than emit a shape that does not
//! match the proof it was built over.

use stark_proofs::crypto::stark::air::{Air, COSET_SHIFT};
use stark_proofs::recursion_assembly::inner;
use stark_proofs::recursion_assembly::point::Point;
use stark_proofs::shield_params::inner as inner_point;
use std::time::Instant;

mod layout;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    /*
     * Which outer, and at what inner query count, is the point selector's to
     * decide: `transfer` and `queries=N` are read there, and so is the check
     * that the environment authenticates a transfer inner at its own rate.
     * Running at 56 and at 64 and reading the emitted layout is how "does 64
     * still fit the 2^21 budget" becomes a measurement instead of a model.
     */
    let at = Point::from_args(&args);
    let point = at.name();
    /*
     * The output path is the first argument that is not a flag, so every flag
     * has to be named here. Adding `root=` without adding it to this list made
     * the root itself the output filename: the run wrote a structure file
     * called `root=f1b9a630...` into the working directory and put the cache
     * beside it rather than beside the emissions, and reported success.
     */
    let out = args
        .iter()
        .find(|a| !Point::is_flag(a) && a.as_str() != "force-root" && !a.starts_with("root="))
        .cloned()
        .unwrap_or_else(|| match at {
            Point::Transfer { queries } => format!("transfer-{queries}-structure.json"),
            Point::Batch { inners } => format!("batch-{inners}-structure.json"),
            Point::Spend { .. } => "spend-structure.json".into(),
            Point::Settlement => "real-structure.json".into(),
            Point::Wrap => "wrap-structure.json".into(),
        });

    let h = inner::hasher();
    let t0 = Instant::now();
    let mut asm = match at.assemble_wired(Point::emit_wiring()) {
        Ok(asm) => asm,
        Err(why) => {
            eprintln!("{why}");
            std::process::exit(2);
        }
    };
    eprintln!("assembled {point} in {:?}", t0.elapsed());

    let t1 = Instant::now();
    let ok = stark_proofs::witness_satisfies_public(&asm.wired, &asm.witness);
    eprintln!("satisfies in {:?}: {ok}", t1.elapsed());
    if !ok {
        eprintln!("the full-coverage assembly does not satisfy; refusing to emit its shape");
        std::process::exit(1);
    }

    /*
     * The witness is read by the satisfaction walk and by nothing after it. The
     * shape and the layout come from the wired AIR and the layout alone, so the
     * witness goes now rather than sit under the outer periodic root's working set.
     */
    drop(core::mem::take(&mut asm.witness));

    /*
     * The numbers a re-gate compares first, on one line so they cannot be missed.
     * The evaluation domain is 2 * next_pow2(degree * 2^log_trace_len), so the
     * log trace length alone fixes it only while the degree stays at or under 16.
     * The degree is printed beside it rather than assumed, and the domain is
     * derived here from both, so a degree that moved underneath a confirmed log
     * length cannot arrive looking like a sizing success.
     */
    let degree = asm.wired.constraint_degree();
    let log_trace_len = asm.wired.log_trace_len();
    let log_domain = (2 * (degree << log_trace_len).next_power_of_two()).trailing_zeros();
    /*
     * The outer degree is the larger of the region degree and the widest group,
     * plus 2, and on this shape the widest group is what pins it. Its width is
     * printed beside the degree because it is the quantity one step from moving
     * the degree, and the domain with it.
     */
    let max_group_width = asm
        .wired
        .group_params()
        .iter()
        .map(|(cols, _, _)| cols.len())
        .max()
        .unwrap_or(0);
    /*
     * Two query counts, named apart. The inner count is the number of inner
     * proof queries the recursion attests, the per query region blocks in the
     * layout; it is what `n_q` has always been. The outer count is the outer's
     * own FRI query count, a parameter of whoever proves it, not of the
     * assembly, and for the chain it is the settlement point's. A verifier that
     * multiplies per query gas by the wrong one is off by their ratio.
     */
    let outer_n_queries = inner_point::N_QUERIES;
    /*
     * The rest of the outer's proving point, emitted rather than assumed. The
     * grind is the proof of work bits the verifier must demand: a proof ground
     * to 16 clears a check of 8, so a verifier that enforced the wrong number
     * would accept identically and only the published bound would be wrong.
     * The blowup sets the outer's evaluation domain, which is (2 * bound) shifted
     * by the extra bits; a rule that derives the domain from the degree and the
     * trace length alone is the rate one half domain, and is short by exactly
     * these bits for a proof at the settlement rate. The log domain is emitted
     * with the extra folded in so nothing downstream derives it without them.
     */
    let grind_bits = inner_point::GRIND_BITS;
    let extra_blowup_bits = inner_point::EXTRA_BLOWUP_BITS;
    let outer_log_domain = log_domain + extra_blowup_bits;
    /*
     * The composition coefficient count the transcript draws before z: one per
     * transition constraint and one per boundary. A verifier that burns one draw
     * too few or too many squeezes a different z, and every quantity after it,
     * the deep coefficients, the consistency indices, the fold positions,
     * diverges in a way that reads as a bad proof rather than a misconfigured
     * verifier. So the boundary count and the sum are both emitted, and nothing
     * downstream has to reconstruct either.
     */
    let num_transition = asm.wired.num_transition();
    let num_boundary = asm.wired.boundary().len();
    let n_coeffs = num_transition + num_boundary;
    /*
     * The inner's own two counts. The compose region is one fixed-order run, so
     * a verifier that knows where the coefficients start can derive the whole
     * slot map from these rather than carry a transcribed table, and a wrong
     * count moves the derivation instead of failing loudly. They come off the
     * inner AIR the emitter already builds for the periodic root, so nothing
     * downstream has to guess them from the outer's totals.
     */
    let inner_air = stark_proofs::shield_deployed_wired();
    let inner_n_transitions = inner_air.num_transition();
    let inner_boundary = inner_air.boundary();
    let inner_n_boundary = inner_boundary.len();
    /*
     * The inner's boundary constraints themselves, not just how many there are.
     *
     * The count alone lets a reader size the coefficient draw; it does not let
     * one evaluate the quotient cells, and without those the composition at z
     * cannot be computed from proof bytes. At the frozen point these came from
     * a fixture file, which is exactly the hand-carried input this emit exists
     * to remove. They are written in the inner engine's own order, which is the
     * order the coefficients were drawn against, so a consumer pairs the two by
     * index and nothing has to agree about sorting.
     */
    let inner_boundary_json: Vec<String> = inner_boundary
        .iter()
        .map(|(col, row, val)| format!("[{col}, {row}, {}]", val.to_u64()))
        .collect();
    println!(
        "outer     point={point} span={} log_trace_len={log_trace_len} degree={degree} \
         max_group_width={max_group_width} log_domain_rate_half={log_domain} \
         extra_blowup_bits={extra_blowup_bits} log_domain={outer_log_domain} \
         grind_bits={grind_bits} coset_shift={COSET_SHIFT} inner_n_queries={} \
         outer_n_queries={outer_n_queries} trace_width={} num_transition={num_transition} \
         num_boundary={num_boundary} n_coeffs={n_coeffs}",
        asm.lay.span,
        asm.lay.n_q,
        asm.wired.trace_width()
    );

    let js = stark_proofs::shield_deployed_wired();
    let root = stark_proofs::crypto::stark::air::periodic_root_poseidon(&js, at.inner_extra(), &h);
    let root_hex: String = root
        .iter()
        .map(|l| format!("{:016x}", l.to_u64()))
        .collect::<Vec<_>>()
        .join("");

    /*
     * Read off the same value the prover binary branches on, not written here
     * a second time. A layout that declared what another file decides is a
     * layout that can say an artifact is argued at a transcript point when it
     * is not, which is the shape of the bug this whole line of work removes.
     *
     * Named rather than defaulted, too: a verifier generated from a layout
     * without this could be deployed against a fixed point argument by
     * omission, which is what the outer shipped with until today.
     */
    let (permutation_challenges, permutation_challenge_root) = Point::emit_challenge_source();
    let wiring = Point::emit_wiring().name();
    /*
     * `rounds` rides beside them, in the same spelling every other emitted file
     * uses for the same claim.
     *
     * This file already said the challenges come from the transcript and a
     * transition vector beside it was replayed as though they did not. Both
     * files carried the claim; neither used the other's words for it, so the
     * cross-file gate had nothing to compare and the contradiction sat in the
     * open. One vocabulary is what makes a disagreement mechanical rather than
     * something a reader has to notice.
     */

    let json = format!(
        "{{\n  \"point\": \"{}\",\n  \"n_inners\": {},\n  \
         \"inner_extra_blowup_bits\": {},\n  \"inner_soundness_bits\": {},\n  \
         \"log_trace_len\": {},\n  \"trace_width\": {},\n  \
         \"num_transition\": {},\n  \"num_boundary\": {},\n  \"n_coeffs\": {},\n  \
         \"num_groups\": {},\n  \"constraint_degree\": {},\n  \
         \"inner_log_trace_len\": {},\n  \"inner_trace_width\": {},\n  \"n_queries\": {},\n  \
         \"inner_n_queries\": {},\n  \"outer_n_queries\": {},\n  \"max_group_width\": {},\n  \
         \"grind_bits\": {},\n  \"extra_blowup_bits\": {},\n  \"log_domain\": {},\n  \
         \"coset_shift\": {},\n  \"inner_n_transitions\": {},\n  \
         \"inner_n_boundary\": {},\n  \"outer_fri_queries\": {},\n  \
         \"inner_boundary\": [{}],\n  \
         \"wiring\": \"{}\",\n  \
         \"region_width\": {},\n  \
         \"rounds\": {},\n  \
         \"permutation_challenges\": \"{}\",\n  \
         \"permutation_challenge_root\": {},\n  \
         \"periodic_root_poseidon\": \"{}\"\n}}\n",
        point,
        at.inners(),
        /*
         * The inner's rate and the soundness it buys, emitted rather than
         * left to be inferred from a Poseidon root nobody can read. The
         * other `extra_blowup_bits` in this file is the outer's and says 3
         * whatever the inner did, which is exactly why an 80 bit artifact
         * could look like a 144 bit one.
         */
        at.inner_extra(),
        at.inner_queries() * (1 + at.inner_extra() as usize) + inner_point::GRIND_BITS as usize,
        asm.wired.log_trace_len(),
        asm.wired.trace_width(),
        num_transition,
        num_boundary,
        n_coeffs,
        asm.n_groups,
        asm.wired.constraint_degree(),
        asm.lay.t_inner.trailing_zeros(),
        asm.lay.width_inner,
        asm.lay.n_q,
        asm.lay.n_q,
        outer_n_queries,
        max_group_width,
        grind_bits,
        extra_blowup_bits,
        outer_log_domain,
        COSET_SHIFT,
        inner_n_transitions,
        inner_n_boundary,
        /*
         * The same value as `outer_n_queries` under the name that says which
         * FRI it counts. The old key stays for one release so a reader pinned
         * to it does not break; after that the ambiguous name goes, because a
         * count of 32 sitting beside a 64 query transfer point is exactly the
         * pair a verifier multiplies the wrong way round.
         */
        outer_n_queries,
        inner_boundary_json.join(", "),
        /*
         * How the copy constraint is shaped: "packed" is one grand product per
         * bin-packed group, "chained" is one permutation over every wired
         * column carried through accumulators. The two have different periodic
         * sets and different roots, so a verifier built from a layout that did
         * not say which one it describes would walk the wrong number of sigma
         * columns and blame the proof.
         */
        wiring,
        /*
         * Where the row splits: columns below this authenticate under the
         * first round's root, columns from here up under the second. It is
         * the codec's `regionWidth`, and a verifier holds it as an immutable
         * set from this file. A verifier that took it from the proof would
         * be checking two roots against halves the prover chose.
         *
         * Distinct from the per kind `region_width` in the layout file, which
         * is one kind's trace width and has nothing to do with the split.
         */
        asm.wired.region_width(),
        /*
         * Where the copy constraint's challenges come from, and which root
         * they are drawn against. Required, with no default, so a verifier
         * generated from this file cannot be deployed against a fixed point
         * argument by omission.
         *
         * "constant" means beta and gamma are circuit constants the prover
         * reads off this layout before choosing its trace, which makes the
         * grand product argue nothing: a prover could break a copy constraint
         * and still satisfy it. A contract handed "constant" should refuse,
         * exactly as it refuses an
         * 80 bit inner rate.
         *
         * "transcript" means they are drawn after the named root is absorbed,
         * which is the two round prover. The root named is the first round's,
         * over the region columns alone, and it travels in the proof as
         * `trace_root`.
         */
        Point::emit_rounds(),
        permutation_challenges,
        permutation_challenge_root,
        root_hex,
    );
    std::fs::write(&out, &json).expect("write structure");
    println!("{json}");
    println!("wrote {out}");

    layout::emit(&asm, &at, &args, &out, &json);
}
