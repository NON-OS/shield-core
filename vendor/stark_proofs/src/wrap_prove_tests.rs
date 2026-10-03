// NONOS Operating System (AGPL-3.0-or-later)

//! The wrap in program form: assembled over the typed outer, its wiring held
//! class by class, assembled at full cap, and proved. The cap-two and full
//! outers are proved under Poseidon once and read back from a cache named
//! by `NONOS_WRAP_CACHE`, because each is most of an hour on a large server.

use crate::crypto::stark::air::{Air, Permuted, Poseidon};
use crate::crypto::stark::field::Fp;
use crate::recursion_assembly::anchors::Anchors;
use crate::recursion_assembly::inner::hasher;
use crate::recursion_assembly::point::Point;
use crate::recursion_assembly::{assemble_over_gen_form, ComposeForm, Tamper};

const CAP: usize = 2;

/// The shared kinds precede the first per-query block, which starts at the
/// DEEP quotient.
fn shared_kinds(bodies: &[(&str, &str)]) -> usize {
    bodies.iter().position(|b| b.0 == "deep").expect("a per-query block")
}

/// The wrap in its own form: the composition over the outer as a three
/// column program, the operands wired, the outputs pinned to zero. The
/// witness assembled that way satisfies the wrap's AIR, which is the claim
/// that the program form and the wide form enforce the same thing.
#[test]
#[ignore = "release tier: proves the cap-two outer under Poseidon"]
fn the_wrap_assembles_as_a_program_over_the_typed_outer() {
    let h: Poseidon = hasher();
    let inner = packed_typed_outer(&h);
    let wrap = assemble_over_gen_form(
        &h,
        inner,
        Tamper::None,
        CAP,
        Point::emit_wiring(),
        Anchors::Collapsed,
        ComposeForm::Program,
    );
    let w = Air::trace_width(&wrap.gen);
    let p = wrap.gen.periodic_columns().len();
    std::println!(
        "the wrap as a program: width {w}, region_width {}, transitions {}, boundaries {}, \
         periodic {p}, log rows {}, n_deep_terms {}",
        Permuted::region_width(&wrap.gen),
        Air::num_transition(&wrap.gen),
        wrap.gen.boundary().len(),
        Air::log_trace_len(&wrap.gen),
        2 * w + p + 1
    );
    let shapes = wrap.gen.wired().region_shapes();
    let shared = shared_kinds(&wrap.kind_bodies);
    let per_q = wrap.kind_bodies.len() - shared;
    let mut rows_by_kind = alloc::vec![0usize; wrap.kind_bodies.len()];
    let mut width_by_kind = alloc::vec![0usize; wrap.kind_bodies.len()];
    for (i, &(width, rows)) in shapes.iter().enumerate() {
        let k = if i < shared { i } else { shared + (i - shared) % per_q };
        rows_by_kind[k] += rows;
        width_by_kind[k] = width;
    }
    for (k, (body, role)) in wrap.kind_bodies.iter().enumerate() {
        std::println!("  rows {:>9}  width {:>5}  {body}/{role}", rows_by_kind[k], width_by_kind[k]);
    }
    let bad = crate::witness_satisfies::violations(&wrap.gen, &wrap.witness, 16);
    let offs = &wrap.region_offsets;
    for (row, lane) in &bad {
        let region = offs.iter().rposition(|&o| o <= *row).unwrap_or(0);
        let k = if region < shared { region } else { shared + (region - shared) % per_q };
        std::println!(
            "violation at row {row} lane {lane}: region {region} ({}/{}) local row {}",
            wrap.kind_bodies[k].0,
            wrap.kind_bodies[k].1,
            row - offs[region]
        );
    }
    assert!(bad.is_empty(), "the wrap's witness in the program form does not satisfy its AIR: {bad:?}");
}

/// The typed outer proved under Poseidon and packed as an inner, from a
/// cache when one is named: proving the cap-two outer is forty minutes on
/// a server and the proof is the same every time, so a diagnostic that needs
/// it four times an evening reads it back instead. `NONOS_WRAP_CACHE` names
/// the directory; unset, it proves.
fn packed_typed_outer(h: &Poseidon) -> crate::wrap::OuterInner {
    packed_typed_outer_at(h, CAP)
}

/// The same at any cap; `usize::MAX` is the outer as deployed, every query.
fn packed_typed_outer_at(h: &Poseidon, cap: usize) -> crate::wrap::OuterInner {
    let cache = std::env::var("NONOS_WRAP_CACHE").ok().map(std::path::PathBuf::from);
    crate::wrap::packed_outer(h, cap, cache.as_deref())
}

/// Every wiring class of the wrap in program form holds one value across
/// its cells, or the first that does not is named cell by cell. The
/// product closure that failed is the sum of exactly this.
#[test]
#[ignore = "release tier: proves or reads the cap-two outer under Poseidon"]
fn the_wraps_wiring_classes_hold_in_program_form() {
    let h: Poseidon = hasher();
    let inner = packed_typed_outer(&h);
    let wrap = assemble_over_gen_form(
        &h,
        inner,
        Tamper::None,
        CAP,
        Point::emit_wiring(),
        Anchors::Collapsed,
        ComposeForm::Program,
    );
    let width = Permuted::region_width(&wrap.gen);
    let full = Air::trace_width(&wrap.gen);
    let binds = crate::recursion_assembly::build::binds_for(&wrap.lay);
    let classes = crate::recursion_assembly::groups::wiring_classes(&binds, wrap.lay.span, width);
    let offs = &wrap.region_offsets;
    let shared = shared_kinds(&wrap.kind_bodies);
    let per_q = wrap.kind_bodies.len() - shared;
    let name = |row: usize| {
        let region = offs.iter().rposition(|&o| o <= row).unwrap_or(0);
        let k = if region < shared { region } else { shared + (region - shared) % per_q };
        (region, wrap.kind_bodies[k].1, row - offs[region])
    };
    let mut bad = 0usize;
    for class in &classes {
        let vals: Vec<Fp> = class.iter().map(|&c| wrap.witness[(c / width) * full + c % width]).collect();
        if vals.iter().any(|v| *v != vals[0]) {
            bad += 1;
            if bad <= 3 {
                std::println!("class of {} cells disagrees:", class.len());
                for (&c, v) in class.iter().zip(&vals).take(12) {
                    let (region, role, local) = name(c / width);
                    std::println!("  row {} col {} = {}   region {region} ({role}) local row {local}", c / width, c % width, v.to_u64());
                }
            }
        }
    }
    std::println!("{} classes, {bad} disagree", classes.len());
    assert_eq!(bad, 0, "{bad} wiring classes hold unequal values");
}

/// The wrap in program form over the outer as deployed, every query: its
/// real rows by region and its width, and the witness satisfying. This is
/// the shape the one transaction proof has.
#[test]
#[ignore = "release tier: proves or reads the full outer under Poseidon"]
fn the_wrap_assembles_as_a_program_at_full_cap() {
    let h: Poseidon = hasher();
    let inner = packed_typed_outer_at(&h, usize::MAX);
    let wrap = assemble_over_gen_form(
        &h,
        inner,
        Tamper::None,
        usize::MAX,
        Point::emit_wiring(),
        Anchors::Collapsed,
        ComposeForm::Program,
    );
    let w = Air::trace_width(&wrap.gen);
    let p = wrap.gen.periodic_columns().len();
    std::println!(
        "the wrap at full cap: width {w}, region_width {}, transitions {}, boundaries {}, periodic {p}, log rows {}, n_deep_terms {}",
        Permuted::region_width(&wrap.gen),
        Air::num_transition(&wrap.gen),
        wrap.gen.boundary().len(),
        Air::log_trace_len(&wrap.gen),
        2 * w + p + 1
    );
    let shapes = wrap.gen.wired().region_shapes();
    let shared = shared_kinds(&wrap.kind_bodies);
    let per_q = wrap.kind_bodies.len() - shared;
    let mut rows_by_kind = alloc::vec![0usize; wrap.kind_bodies.len()];
    for (i, &(_, rows)) in shapes.iter().enumerate() {
        let k = if i < shared { i } else { shared + (i - shared) % per_q };
        rows_by_kind[k] += rows;
    }
    let total: usize = rows_by_kind.iter().sum();
    for (k, (body, role)) in wrap.kind_bodies.iter().enumerate() {
        std::println!("  rows {:>9}  {:5.1}%  {body}/{role}", rows_by_kind[k], 100.0 * rows_by_kind[k] as f64 / total as f64);
    }
    std::println!("  rows {total:>9} total, padded to 2^{}", Air::log_trace_len(&wrap.gen));
    let bad = crate::witness_satisfies::violations(&wrap.gen, &wrap.witness, 8);
    assert!(bad.is_empty(), "the full cap wrap does not satisfy: {bad:?}");
}

/// The wrap proved with the chain's transcript at the deployment point and
/// verified back from its bytes: the first proof of the settlement outer's
/// verification. Written to `NONOS_WRAP_OUT` when set.
#[test]
#[ignore = "release tier: proves the wrap"]
fn the_wrap_proves_at_the_deployment_rate() {
    use crate::host::{point_from_args, prove_outer};
    use crate::recursion_assembly::Assembly;
    let h: Poseidon = hasher();
    let inner = packed_typed_outer_at(&h, usize::MAX);
    let wrap = assemble_over_gen_form(
        &h,
        inner,
        Tamper::None,
        usize::MAX,
        Point::emit_wiring(),
        Anchors::Collapsed,
        ComposeForm::Program,
    );
    let asm = Assembly {
        wired: wrap.gen.into_wired(),
        witness: wrap.witness,
        lay: wrap.lay,
        publics: wrap.publics,
        n_groups: wrap.n_groups,
        region_offsets: wrap.region_offsets,
        kind_bodies: wrap.kind_bodies,
    };
    let out = std::env::var("NONOS_WRAP_OUT").unwrap_or_else(|_| "wrap-1.proof".to_string());
    let settled = prove_outer(&h, asm, &out, None, point_from_args(&[]));
    std::println!("the wrap proved: {} bytes, periodic root {}", settled.bytes, settled.root_hex);
    assert!(settled.bytes > 0);
}

/// The wrap at the one-transaction point over the outer at the point under
/// it: the proof the chain verifies in one call. The outer proves at sixteen
/// queries, from `NONOS_WRAP_CACHE` when a proof at that point is there;
/// the wrap is written to `NONOS_WRAP_OUT`.
#[test]
#[ignore = "release tier: proves the outer at sixteen queries and the wrap at the one-transaction point"]
fn the_wrap_proves_at_the_one_transaction_point() {
    use crate::host::{point_from_args, prove_outer};
    use crate::recursion_assembly::Assembly;
    use crate::wrap::{packed_outer_at, OuterPoint};
    let h: Poseidon = hasher();
    let cache = std::env::var("NONOS_WRAP_CACHE").ok().map(std::path::PathBuf::from);
    let inner = packed_outer_at(&h, usize::MAX, cache.as_deref(), OuterPoint::UNDER_WRAP);
    let wrap = assemble_over_gen_form(
        &h,
        inner,
        Tamper::None,
        usize::MAX,
        Point::emit_wiring(),
        Anchors::Collapsed,
        ComposeForm::Program,
    );
    let asm = Assembly {
        wired: wrap.gen.into_wired(),
        witness: wrap.witness,
        lay: wrap.lay,
        publics: wrap.publics,
        n_groups: wrap.n_groups,
        region_offsets: wrap.region_offsets,
        kind_bodies: wrap.kind_bodies,
    };
    let out = std::env::var("NONOS_WRAP_OUT").unwrap_or_else(|_| "wrap-one.proof".to_string());
    let settled = prove_outer(&h, asm, &out, None, point_from_args(&["point=settlement".to_string()]));
    std::println!(
        "the wrap proved at the one-transaction point: {} bytes, periodic root {}",
        settled.bytes,
        settled.root_hex
    );
}

/// The settlement outer proved in program form. The strip form pays its
/// widest region at every row: 662 columns and 1,099 periodic columns over
/// 262,144 rows, of which 3.9 per cent hold anything. Recording the
/// composition as a straight-line program makes it 41 and 119 at 61.9 per
/// cent, and a verifier hashes a trace row and a periodic row at every
/// query, so both numbers are the proof's size and the walk's gas as much as
/// they are the prover's time.
#[test]
#[ignore = "release tier: proves the settlement outer in program form"]
fn the_outer_proves_as_a_program() {
    use crate::host::{point_from_args, prove_outer};
    use crate::recursion_assembly::inner::shield_join_split;
    use crate::recursion_assembly::{assemble_over_gen_form, Assembly};
    let h: Poseidon = hasher();
    let outer = assemble_over_gen_form(
        &h,
        shield_join_split(&h),
        Tamper::None,
        usize::MAX,
        Point::emit_wiring(),
        Anchors::Collapsed,
        ComposeForm::Program,
    );
    let asm = Assembly {
        wired: outer.gen.into_wired(),
        witness: outer.witness,
        lay: outer.lay,
        publics: outer.publics,
        n_groups: outer.n_groups,
        region_offsets: outer.region_offsets,
        kind_bodies: outer.kind_bodies,
    };
    let out = std::env::var("NONOS_OUTER_OUT").unwrap_or_else(|_| "outer-program.proof".to_string());
    // The point is a parameter of the run, so the same gate proves the
    // deployment shape and the one-transaction shape without a second test.
    let args: Vec<String> = std::env::var("NONOS_OUTER_POINT")
        .ok()
        .map(|p| alloc::vec![alloc::format!("point={p}")])
        .unwrap_or_default();
    // A periodic root names a cached tree beside `out`; the tree is the
    // circuit's and the same for every proof of it, so a run that names it
    // skips the largest fixed cost. The prover refuses a tree whose root moved.
    let root = std::env::var("NONOS_OUTER_ROOT").ok();
    let settled = prove_outer(&h, asm, &out, root.as_deref(), point_from_args(&args));
    std::println!(
        "the outer proved as a program: {} bytes, periodic root {}",
        settled.bytes,
        settled.root_hex
    );
}
