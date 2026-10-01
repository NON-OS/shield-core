// NONOS Operating System (AGPL-3.0-or-later)
//! An outer AIR's transition vector at the out-of-domain point, and the
//! composition the proof determines there.
//!
//! This is the per lane gate the frozen point had and settlement did not. With
//! the 389 values in hand a consumer diffs lane by lane and the disagreement
//! names the kind; without them a wrong body is one wrong number at the end of
//! a sum of 1,579 terms, and bisecting that is guesswork.
//!
//! It costs an assembly and one evaluation of the AIR. Nothing is proved and
//! nothing is hashed: the frame at z and the periodic values at z are already
//! in the artifact, so this reads them out and calls the same
//! `transition_ext` the prover and the verifier both call.
//!
//! `comp_z` is emitted beside them, replayed from the transcript's own prefix
//! at the proof's rate. It can also be recovered by solving the DEEP identity
//! at one query and closing the others, so a walk over a new artifact starts
//! from a number two independent derivations agree on.
//!
//! The inputs are echoed back alongside the outputs on purpose. If the
//! consumer's decode of the frame or of the sidecar claims differs from this
//! one, the transition values would differ for a reason that has nothing to do
//! with a body being wrong, and the two sides need to rule that out before
//! reading anything into a lane diff.
//!
//! The point comes from the selector: settlement by default, `transfer` with
//! `queries=N` for the recursion over a transfer inner. The artifact must be
//! the one proved over that outer, and the frame width check below is what
//! says so.

use stark_proofs::crypto::stark::air::replay_pre::replay_comp_z_pre;
use stark_proofs::crypto::stark::air::{
    deserialize_proof_ext, serialize_proof_ext, Air, AirExt, GenRegion, StarkProofExtPre,
    WiredMultiGen,
};
use stark_proofs::crypto::stark::field::{Fp, Fp2};
use stark_proofs::crypto::stark::merkle::DIGEST_BYTES;
use stark_proofs::proof_wire::ROUNDS_HEADER;
use stark_proofs::recursion_assembly::point::Point;
use stark_proofs::recursion_assembly::AssemblyGen;
use stark_proofs::shield_params::inner as inner_point;
use std::time::Instant;

/// Read the sidecar's claims at z, which follow the base proof encoding.
///
/// The offset is recovered by re-serialising the parsed base rather than by
/// assuming a length: the base encoding is frozen but it is frozen somewhere
/// else, and a constant here would be a second opinion about it.
fn claims_at_z(bytes: &[u8], base_len: usize) -> Vec<Fp2> {
    let n = u32::from_le_bytes(bytes[base_len..base_len + 4].try_into().unwrap()) as usize;
    let mut out = Vec::with_capacity(n);
    let mut p = base_len + 4;
    for _ in 0..n {
        let c0 = u64::from_le_bytes(bytes[p..p + 8].try_into().unwrap());
        let c1 = u64::from_le_bytes(bytes[p + 8..p + 16].try_into().unwrap());
        out.push(Fp2 {
            c0: Fp::from_u64(c0),
            c1: Fp::from_u64(c1),
        });
        p += 16;
    }
    out
}

fn f2(v: &Fp2) -> String {
    format!("[{}, {}]", v.c0.to_u64(), v.c1.to_u64())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let point = Point::from_args(&args);
    /*
     * `unbound` replays the transcript with no public inputs absorbed, for an
     * artifact proved before the binding existed. Such a proof is a
     * measurement of the prover and not a proof about a batch, and its
     * comp_z is the one under the transcript it was actually made with.
     */
    let unbound = args.iter().any(|a| a == "unbound");
    /*
     * Two positional arguments, the artifact and the output, in that order,
     * after the point's own flags are set aside.
     */
    let mut positional = args
        .iter()
        .filter(|a| !Point::is_flag(a) && a.as_str() != "unbound");
    let proof_path = positional
        .next()
        .cloned()
        .unwrap_or_else(|| format!("emissions/{}-pre.proof", point.name()));
    let out = positional
        .next()
        .cloned()
        .unwrap_or_else(|| "transitions-z.json".into());

    /*
     * A two round artifact leads with the permutation root and the row split,
     * so the one round encoding this reads starts past them. The point decides
     * and the bytes are not consulted: a reader that sniffed the header would
     * be a reader that accepts both encodings, and a prover who picks the
     * encoding picks the one without a copy commitment.
     */
    let raw = std::fs::read(&proof_path).expect("read the artifact");
    let rounds = Point::emit_rounds();
    let bytes = if rounds {
        &raw[ROUNDS_HEADER..]
    } else {
        &raw[..]
    };
    /*
     * The second round's root, from the header it leads with. It is not
     * decoration: the transcript squeezes beta and gamma against the region
     * root and absorbs this before it draws a single coefficient, so a replay
     * without it lands on a point the proof never opened. This binary replayed
     * without it and printed that point beside the artifact.
     */
    let perm_root: Option<[u8; 32]> = rounds.then(|| {
        let mut d = [0u8; 32];
        d[..DIGEST_BYTES].copy_from_slice(&raw[..DIGEST_BYTES]);
        d
    });
    let proof = deserialize_proof_ext(bytes).expect("the base half must parse");
    let base_len = serialize_proof_ext(&proof).len();
    let periodic_z = claims_at_z(bytes, base_len);
    let frame = &proof.ood_frame;
    eprintln!(
        "artifact  {} bytes, base {} bytes, frame {} cells, claims {}",
        bytes.len(),
        base_len,
        frame.len(),
        periodic_z.len()
    );

    /*
     * Held by name, because the fused vector alone was not enough. The contracts
     * lane ported every region body against it and matched none of 162 lanes:
     * at the out-of-domain point every kind contributes to every lane below its
     * arity, weighted by its selector's value at z, so a port that dispatches
     * one body per lane cannot agree with the sum. What it can agree with is
     * each body's own output on its own window and periodic slice, and that is
     * what the named regions make available.
     */
    let t0 = Instant::now();
    let mut asm = match point.assemble_gen(
        Point::emit_wiring(),
        stark_proofs::recursion_assembly::anchors::DEPLOYED,
    ) {
        Ok(asm) => asm,
        Err(why) => {
            eprintln!("{why}");
            std::process::exit(2);
        }
    };
    eprintln!("assembled {} in {:?}", point.name(), t0.elapsed());

    let width = Air::trace_width(&asm.gen);
    let window = Air::window_size(&asm.gen);
    if frame.len() != width * window {
        eprintln!(
            "the frame is {} cells but the AIR is {} wide over a {} row window; \
             these are not the same circuit",
            frame.len(),
            width,
            window
        );
        std::process::exit(1);
    }

    /*
     * The same call the prover makes inside comp_at_z and the verifier makes
     * when it recomputes the composition. Nothing here is a reimplementation:
     * if this disagrees with a consumer, the consumer's bodies disagree with
     * the engine's.
     */
    /*
     * The replay runs first, and it is not only for comp_z.
     *
     * It is what puts the drawn pair into the AIR. An assembled AIR holds the
     * constructor placeholder, which is the pair the recorded forgery was built
     * at, and this binary used to evaluate all 248 lanes over it: honest
     * arithmetic about a circuit nobody proved. The only substitution that
     * reproduced the published value was 5 and 7.
     *
     * So: replay, then evaluate. The order is the finding.
     */
    let pre = StarkProofExtPre {
        deep_nonce: 0,
        proof,
        periodic_z,
        openings: Vec::new(),
    };
    /*
     * Under the assembly's own public inputs, which the prover absorbed first
     * of all. A replay without them derives a different z, and its comp_z is
     * the composition at a point the proof never opened.
     */
    let publics_owned = asm.publics.clone();
    let absorbed: &[Fp] = if unbound { &[] } else { &publics_owned };
    let replayed = replay_comp_z_pre(
        &mut asm.gen,
        &pre,
        perm_root.as_ref(),
        inner_point::EXTRA_BLOWUP_BITS,
        absorbed,
    )
    .unwrap_or_else(|why| panic!("the proof does not replay: {why}"));
    eprintln!(
        "comp_z    c0 {} c1 {} (z c0 {} c1 {}, {} coefficients, {} publics absorbed, \
         rounds {})",
        replayed.comp_z.c0.to_u64(),
        replayed.comp_z.c1.to_u64(),
        replayed.z.c0.to_u64(),
        replayed.z.c1.to_u64(),
        replayed.coeffs.len(),
        absorbed.len(),
        rounds
    );
    /*
     * The pair is in the AIR now, and the artifact says which one it is. A
     * consumer that reproduces a lane with a different pair has reproduced a
     * different circuit, and until this field existed there was nothing in the
     * file to check that against.
     */
    let (beta, gamma) = replayed
        .challenges
        .map(|(b, g)| (b.c0, g.c0))
        .expect("a two round artifact draws a pair; a one round one is not emitted here");
    assert_eq!(
        asm.gen.wired().n_challenges(),
        2,
        "the AIR did not adopt the drawn pair; every lane below would be at the \
         constructor placeholder, which is the pair the recorded forgery used"
    );
    eprintln!(
        "challenge beta {} gamma {} drawn from the region root",
        beta.to_u64(),
        gamma.to_u64()
    );

    /*
     * The same combination the prover and verifier make, with each kind's
     * body caught on the way through. `combine` evaluates one region per kind
     * on a window repacked to that region's width and on that kind's periodic
     * slice, and adds its output into every lane weighted by the kind's
     * selector at z, which is periodic value `k` for kind `k`. A consumer
     * matches each body against its own row here before it sums anything.
     */
    let t1 = Instant::now();
    let caught: core::cell::RefCell<Vec<Caught>> = core::cell::RefCell::new(Vec::new());
    let transitions = asm.gen.wired().transition_generic_at::<Fp2>(
        &pre.proof.ood_frame,
        &pre.periodic_z,
        &[],
        |i, local, slice| {
            let values = asm.gen.regions()[i].transition_gen::<Fp2>(local, slice);
            caught.borrow_mut().push(Caught {
                region: i,
                local: local.to_vec(),
                slice: slice.to_vec(),
                values: values.clone(),
            });
            values
        },
    );
    assert!(
        transitions == AirExt::transition_ext(&asm.gen, &pre.proof.ood_frame, &pre.periodic_z),
        "the named regions and the boxed engine disagree at z"
    );
    eprintln!(
        "evaluated {} transitions over {} kinds in {:?}",
        transitions.len(),
        caught.borrow().len(),
        t1.elapsed()
    );
    let shared = 4usize;
    let per_q = asm.kind_bodies.len() - shared;
    let kinds_z: Vec<String> = caught
        .borrow()
        .iter()
        .map(
            |Caught {
                 region: i,
                 local,
                 slice,
                 values,
             }| {
                let k = if *i < shared {
                    *i
                } else {
                    shared + (*i - shared) % per_q
                };
                let (body, role) = asm.kind_bodies[k];
                format!(
                    "{{\"kind\": {k}, \"body\": \"{body}\", \"role\": \"{role}\", \
                 \"selector_z\": {}, \"region\": {i}, \"arity\": {}, \
                 \"local_window\": [{}], \"periodic_slice\": [{}], \"values\": [{}]}}",
                    f2(&pre.periodic_z[k]),
                    values.len(),
                    local.iter().map(f2).collect::<Vec<_>>().join(", "),
                    slice.iter().map(f2).collect::<Vec<_>>().join(", "),
                    values.iter().map(f2).collect::<Vec<_>>().join(", ")
                )
            },
        )
        .collect();

    let publics_s: Vec<String> = absorbed.iter().map(|v| v.to_u64().to_string()).collect();
    let frame = &pre.proof.ood_frame;
    let periodic_z = &pre.periodic_z;

    let values: Vec<String> = transitions.iter().map(f2).collect();
    let claims: Vec<String> = periodic_z.iter().map(f2).collect();
    let frame_s: Vec<String> = frame.iter().map(f2).collect();

    /*
     * Where the lanes divide, so a diff can be read without holding the emit
     * open beside it: region transitions overlay from zero and the groups
     * follow them, one lane each.
     */
    let n_groups = Air::num_transition(&asm.gen) - region_lanes(&asm);
    let json = format!(
        "{{\n  \"point\": \"{}\",\n  \"artifact\": \"{}\",\n  \
         \"rounds\": {},\n  \"wiring\": \"{}\",\n  \
         \"beta\": {},\n  \"gamma\": {},\n  \
         \"trace_width\": {},\n  \"window_size\": {},\n  \
         \"log_trace_len\": {},\n  \"num_transition\": {},\n  \
         \"region_lanes\": {},\n  \"group_lanes\": {},\n  \
         \"n_claims\": {},\n  \"n_frame_cells\": {},\n  \
         \"extra_blowup_bits\": {},\n  \"n_coeffs\": {},\n  \
         \"n_publics\": {},\n  \"publics\": [{}],\n  \
         \"z\": {},\n  \"comp_z\": {},\n  \
         \"lane_rule\": \"lane c = sum over kinds k with arity > c of selector_z[k] * \
         values[k][c], each body on its local_window (the first region_width columns of \
         each window row) and its periodic_slice; the group lanes follow\",\n  \
         \"kinds_z\": [\n    {}\n  ],\n  \
         \"transitions_z\": [\n    {}\n  ],\n  \
         \"ood_frame\": [\n    {}\n  ],\n  \
         \"periodic_z\": [\n    {}\n  ]\n}}\n",
        point.name(),
        proof_path,
        rounds,
        Point::emit_wiring().name(),
        beta.to_u64(),
        gamma.to_u64(),
        width,
        window,
        Air::log_trace_len(&asm.gen),
        Air::num_transition(&asm.gen),
        region_lanes(&asm),
        n_groups,
        periodic_z.len(),
        frame.len(),
        inner_point::EXTRA_BLOWUP_BITS,
        replayed.coeffs.len(),
        absorbed.len(),
        publics_s.join(", "),
        f2(&replayed.z),
        f2(&replayed.comp_z),
        kinds_z.join(",\n    "),
        values.join(",\n    "),
        frame_s.join(",\n    "),
        claims.join(",\n    "),
    );
    std::fs::write(&out, &json).expect("write the transition vector");
    eprintln!("wrote {out}, {} lanes", transitions.len());
}

/// The number of lanes the region kinds overlay into, which is the maximum
/// arity over the kinds rather than their sum.
/// One region body evaluated at z on its own window: which region, what it
/// read, what it produced. Emitted per kind so a body is held on its own.
struct Caught {
    region: usize,
    local: Vec<Fp2>,
    slice: Vec<Fp2>,
    values: Vec<Fp2>,
}

fn region_lanes(asm: &AssemblyGen<WiredMultiGen>) -> usize {
    asm.gen
        .wired()
        .kind_map()
        .iter()
        .map(|&(_, _, arity, _, _)| arity)
        .max()
        .unwrap_or(0)
}
