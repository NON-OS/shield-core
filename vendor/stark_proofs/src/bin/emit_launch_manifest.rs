// NONOS Operating System (AGPL-3.0-or-later)
//! The launch circuit's structure and proof layout, derived from the circuit
//! itself, for a verifier generator to read rather than a person to type.
//!
//!     emit_launch_manifest <structure.json> <layout.json>
//!
//! `structure.json` holds what the verifier's arithmetic depends on: the
//! shape, where the public words are pinned, how every challenge is drawn, the
//! grinds, the periodic root and the 36 public words by name, with the rule
//! that turns an address into its four limbs. `layout.json` holds every byte
//! offset of a proof at the launch point, the nonce region included. Both
//! come from the same AIR a wallet proves under, built here from a fixture
//! spend at the deployed depth; the shape does not depend on the spend.

use stark_proofs::crypto::stark::air::replay_pre::{commit_grind_bits, grind_chunks};
use stark_proofs::crypto::stark::air::{
    domain_params_blown, periodic_root, Air, AirExt, Permuted, COSET_SHIFT,
};
use stark_proofs::crypto::stark::fri_ext::{COMMIT_GRIND_BITS, GRIND_CHUNKS};
use stark_proofs::crypto::stark::merkle::DIGEST_BYTES;
use stark_proofs::host::die;
use stark_proofs::proof_wire::HEADER_BYTES;
use stark_proofs::proof_wire::{Layout, ParamSet};
use stark_proofs::shield::join::publics as w;
use stark_proofs::shield::join::{
    address_from_u64, join_split_at, Settle, Spend, ADDRESS_LIMB_BITS,
};
use stark_proofs::shield::key::Break;
use stark_proofs::shield::member::TREE_DEPTH;
use stark_proofs::shield::note::Note;
use stark_proofs::shield::test::fixture::{owned, plain, secret};
use stark_proofs::shield_params::direct;

/// The provable bits of the two FRI error terms, docs/12-soundness.md
/// Section 2.1, in the Johnson regime with multiplicity `m` = 3 over F_p^2.
/// Query phase: `q * -log2(sqrt(rho) * (1 + 1/(2m))) + grind`. Commit phase:
/// `-log2((m + 1/2)^7 * N^2 / (3 * rho^(3/2) * |K|)) + commit grind`, for an
/// evaluation domain of `N = 2^log_n` points.
fn fri_bits(
    q: usize,
    fri_log_blowup: u32,
    grind: u32,
    commit_grind: u32,
    log_n: u32,
) -> (f64, f64) {
    let m = 3.0f64;
    let rate = 2f64.powi(-(fri_log_blowup as i32));
    let per_query = -(rate.sqrt() * (1.0 + 1.0 / (2.0 * m))).log2();
    let query = q as f64 * per_query + grind as f64;
    let log_k = 2.0 * 18446744069414584321f64.log2();
    let log_err =
        7.0 * (m + 0.5).log2() + 2.0 * log_n as f64 - (3f64.log2() + 1.5 * rate.log2() + log_k);
    (query, -log_err + commit_grind as f64)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (Some(structure_out), Some(layout_out)) = (a.first(), a.get(1)) else {
        die("usage: emit_launch_manifest <structure.json> <layout.json>")
    };
    let (q, grind, extra) = (
        direct::N_QUERIES,
        direct::GRIND_BITS,
        direct::EXTRA_BLOWUP_BITS,
    );

    let sks = [secret(1), secret(2)];
    let notes = [owned(sks[0], 0, 1000), owned(sks[1], 1, 500)];
    let outs: [Note; 2] = [plain(20, 1200), plain(30, 300)];
    let js = join_split_at(
        TREE_DEPTH,
        [
            Spend {
                note: &notes[0],
                sk: sks[0],
            },
            Spend {
                note: &notes[1],
                sk: sks[1],
            },
        ],
        [&outs[0], &outs[1]],
        0,
        0,
        Break::None,
        Settle {
            not_before: 0,
            clearing_price: 0,
            recipient: address_from_u64(0),
            fee_recipient: [0; 20],
        },
        None,
    );
    let air = &js.wired;
    let wired = air.wired();
    let lanes = air.challenge_lanes();
    let params = ParamSet::of(air, q, grind, extra);
    let l = Layout::of(&params);
    let root = periodic_root(air, extra);
    let pins = wired.public_pin_range();
    let pair = air
        .mask_pair()
        .unwrap_or_else(|| die("the launch circuit has no mask pair"));
    // The FRI domain and rate the prover actually uses, from the circuit.
    let (log_n, fri_log_blowup) = domain_params_blown(air, extra);
    let bits = fri_bits(q, fri_log_blowup, grind, commit_grind_bits(lanes), log_n);

    let names = [
        ("note_root", w::NOTE_ROOT, 4),
        ("assoc_root", w::ASSOC_ROOT, 4),
        ("nf0", w::NF0, 4),
        ("nf1", w::NF1, 4),
        ("out_cm0", w::OUT_CM0, 4),
        ("out_cm1", w::OUT_CM1, 4),
        ("public_amount", w::PUBLIC_AMOUNT, 1),
        ("fee", w::FEE, 1),
        ("asset_id", w::ASSET_ID, 1),
        ("clearing_price", w::CLEARING_PRICE, 1),
        ("recipient", w::RECIPIENT, 4),
        ("fee_recipient", w::FEE_RECIPIENT, 4),
    ];
    let words: Vec<String> = names
        .iter()
        .map(|(n, at, len)| format!("    {{\"name\": \"{n}\", \"at\": {at}, \"words\": {len}}}"))
        .collect();

    let structure = format!(
        "{{\n  \"artifact\": \"launch-structure\",\n  \
         \"point\": {{\"queries\": {q}, \"grind_bits\": {grind}, \"grind_chunks\": {}, \"bits_per_chunk\": {}, \
         \"commit_grind_bits\": {}, \"extra_blowup_bits\": {extra}, \"provable_bits\": {{\"query_phase\": {:.1}, \"commit_phase\": {:.1}, \"minimum\": {:.1}, \"regime\": \"Johnson, m = 3, docs/12-soundness.md 2.1\"}}}},\n  \
         \"periodic_root\": \"{}\",\n  \"params_id\": \"{}\",\n  \"layout_id\": \"{}\",\n  \
         \"shape\": {{\"trace_width\": {}, \"region_width\": {}, \"product_columns\": {}, \"mask_columns\": {}, \
         \"log_trace_len\": {}, \"window\": {}, \"constraint_degree\": {}, \"transitions\": {}, \"boundaries\": {}, \
         \"periodic_columns\": {}, \"coset_shift\": {}, \"digest_bytes\": {}}},\n  \
         \"public_pins\": {{\"boundaries\": [{}, {}], \"count\": {}}},\n  \
         \"challenges\": {{\"lanes\": {lanes}, \"copy_constraint\": \"beta and gamma each in F_p^2: [b0, b1], [g0, g1], transcript tags 0x06/0x07\", \
         \"composition_coefficients\": \"powers of one alpha in F_p^2: alpha^0 .. alpha^(n-1)\", \
         \"deep_coefficients\": \"powers of a second alpha in F_p^2\", \
         \"fri_fold\": \"one challenge in F_p^2 per layer, after the layer root and its commit nonce\"}},\n  \
         \"grinds\": {{\"commit\": \"after each FRI layer root is absorbed: a nonce with {} leading zero bits, absorbed, then the fold challenge\", \
         \"query\": \"after the final layer: {} chained nonces of {} bits, each searched against the state with the previous one absorbed, then the query positions\"}},\n  \
         \"frame\": \"per window row k (z_k = z, g z), one F_p^2 value per column; the mask pair {} and {} is opened as one F_p^2 value: slot {} carries M_{}(z_k) + X M_{}(z_k), with X^2 = 7, and slot {} carries zero, which the verifier requires. DEEP gives column {} the coefficient X times column {}'s\",\n  \
         \"publics\": {{\"words\": {}, \"order\": [\n{}\n  ]}},\n  \
         \"address_limbs\": \"limb i = (uint160(addr) >> {} * i) & (2^{} - 1) for i < 3; limb 3 = uint160(addr) >> 144\"\n}}\n",
        grind_chunks(lanes),
        grind - grind_chunks(lanes).trailing_zeros(),
        commit_grind_bits(lanes),
        bits.0,
        bits.1,
        bits.0.min(bits.1),
        hex(&root[..DIGEST_BYTES]),
        hex(&params.id()),
        hex(&l.id()),
        air.trace_width(),
        air.region_width(),
        wired.product_columns(),
        wired.mask_columns(),
        air.log_trace_len(),
        air.window_size(),
        air.constraint_degree(),
        air.num_transition(),
        air.boundary().len(),
        air.periodic_columns().len(),
        COSET_SHIFT,
        DIGEST_BYTES,
        pins.start,
        pins.end,
        pins.len(),
        COMMIT_GRIND_BITS,
        GRIND_CHUNKS,
        grind - GRIND_CHUNKS.trailing_zeros(),
        pair.0,
        pair.1,
        pair.0,
        pair.0,
        pair.1,
        pair.1,
        pair.1,
        pair.0,
        w::WORDS,
        words.join(",\n"),
        ADDRESS_LIMB_BITS,
        ADDRESS_LIMB_BITS
    );
    std::fs::write(structure_out, structure)
        .unwrap_or_else(|e| die(&format!("cannot write {structure_out}: {e}")));

    let m = l.manifest();
    let query_nonces = params.grind_chunks as usize;
    let fold_nonces = if params.commit_grind_bits != 0 {
        m.fri_layers.len()
    } else {
        0
    };
    let mut body: Vec<String> = vec![
        format!("  \"header_bytes\": {HEADER_BYTES}"),
        format!("  \"offsets_from\": \"the first byte after the {HEADER_BYTES}-byte header; add {HEADER_BYTES} for a position in the proof file\""),
        format!("  \"params_id\": \"{}\"", hex(&m.params_id)),
        format!("  \"layout_id\": \"{}\"", hex(&l.id())),
    ];
    body.extend(
        l.words()
            .into_iter()
            .map(|(n, v)| format!("  \"{}\": {v}", n.to_lowercase())),
    );
    body.push(format!(
        "  \"nonces\": {{\"base\": {}, \"query\": {query_nonces}, \"fold\": {fold_nonces}, \"bytes_each\": 8, \
         \"order\": \"on the wire, the {query_nonces} query nonces in search order, then one per FRI layer, each u64 little endian; the transcript absorbs them in protocol order, each layer nonce after its root and the query nonces after the final layer\", \"end\": {}}}",
        l.fri.end,
        l.fri.end + 8 * (query_nonces + fold_nonces)
    ));
    let layers: Vec<String> = m
        .fri_layers
        .iter()
        .map(|f| {
            format!(
                "    {{\"base\": {}, \"stride\": {}, \"depth\": {}, \"count\": {}}}",
                f.base, f.stride, f.depth, f.count
            )
        })
        .collect();
    body.push(format!("  \"fri_layers\": [\n{}\n  ]", layers.join(",\n")));
    let layout = format!("{{\n{}\n}}\n", body.join(",\n"));
    if l.fri.end + 8 * (query_nonces + fold_nonces) != m.cons_base {
        die("the nonce region does not end where the consistency section begins");
    }
    std::fs::write(layout_out, layout)
        .unwrap_or_else(|e| die(&format!("cannot write {layout_out}: {e}")));
    println!(
        "wrote {structure_out} and {layout_out}: root {}, params {}",
        hex(&root[..DIGEST_BYTES]),
        hex(&params.id())
    );
}
