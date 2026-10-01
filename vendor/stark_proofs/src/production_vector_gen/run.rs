// NONOS Operating System (AGPL-3.0-or-later)
//! The gen: assemble the witness-mode recursion, commit the preprocessed
//! periodic columns, prove at deployment soundness, and emit the vector, the
//! structure, and the intermediates oracle for the contracts tree.

use super::{intermediates, structure, vector};
use crate::crypto::stark::air::{
    periodic_root, stark_prove_ext_preprocessed, stark_verify_ext_preprocessed, Air,
};
use crate::recursion_assembly::{assemble, Tamper};
use alloc::string::String;
use alloc::vec::Vec;

/// Where the contract reference vectors go. Another repo owns them, so the
/// caller names the directory; unset means there is nowhere to write and the
/// generator has nothing to do.
fn spec_dir() -> Option<String> {
    std::env::var("NOX_SPEC_DIR").ok().filter(|d| !d.is_empty())
}

/// The structure alone, without the deployment proof behind it.
///
/// A verifier reads its shape from this file and its inner domain from
/// inner_log_trace_len, so a contract can be wired to the field before anyone
/// waits on a proof. The proof takes an hour; the shape takes seconds, and the
/// shape is what a derivation reads.
#[test]
#[ignore]
fn gen_production_structure() {
    // The recursion outer's reference vectors are v1 artifacts: v2 ships no
    // outer, and docs/17 defines only the launch transcript. Refuse rather than
    // emit vectors from a transcript no document describes.
    if cfg!(feature = "v2") {
        panic!("the production recursive vectors are not generated under v2");
    }
    let Some(spec) = spec_dir() else {
        std::println!("NOX_SPEC_DIR unset, nothing to generate");
        return;
    };
    let asm = assemble(Tamper::None);
    let wired = &asm.wired;

    let ltl = wired.log_trace_len();
    let tt = 1usize << ltl;
    let deg = wired.constraint_degree().max(1);
    let bound = (deg * tt).next_power_of_two();
    let nn = (2 * bound) << 3;
    let log_dn = nn.trailing_zeros();
    let fri_log_blowup = log_dn - bound.trailing_zeros();
    let n_periodic = wired.periodic_columns().len();
    let periodic_root = periodic_root(wired, 3);

    let off_heights: Vec<(usize, usize)> = asm
        .region_offsets
        .iter()
        .enumerate()
        .map(|(ri, &o)| {
            let end = asm
                .region_offsets
                .get(ri + 1)
                .copied()
                .unwrap_or(asm.lay.span);
            (o, end - o)
        })
        .collect();
    let region_transitions = wired.num_transition() - asm.n_groups;
    structure::emit(
        &asm,
        &off_heights,
        fri_log_blowup,
        log_dn,
        n_periodic,
        region_transitions,
        &periodic_root,
        &alloc::format!("{spec}/production-air-structure.json"),
    );
    std::println!(
        "structure: log_trace_len {} inner_log_trace_len {}",
        ltl,
        asm.lay.t_inner.trailing_zeros()
    );
}

#[test]
#[ignore]
fn gen_production_recursive_vector() {
    // The recursion outer's reference vectors are v1 artifacts: v2 ships no
    // outer, and docs/17 defines only the launch transcript. Refuse rather than
    // emit vectors from a transcript no document describes.
    if cfg!(feature = "v2") {
        panic!("the production recursive vectors are not generated under v2");
    }
    let Some(spec) = spec_dir() else {
        std::println!("NOX_SPEC_DIR unset, nothing to generate");
        return;
    };
    let asm = assemble(Tamper::None);
    let wired = &asm.wired;

    let ltl = wired.log_trace_len();
    let tt = 1usize << ltl;
    let deg = wired.constraint_degree().max(1);
    let bound = (deg * tt).next_power_of_two();
    let nn = (2 * bound) << 3; // extra_blowup_bits = 3 -> rate 1/16
    let log_dn = nn.trailing_zeros();
    let fri_log_blowup = log_dn - bound.trailing_zeros();

    // The preprocessed-periodic commitment, through the same helper the prover
    // commits with and a registration recomputes: one object, not agreement.
    let n_periodic = wired.periodic_columns().len();
    let periodic_root = periodic_root(wired, 3);
    std::println!(
        "committed {} periodic columns over 2^{}",
        n_periodic,
        log_dn
    );

    let off_heights: Vec<(usize, usize)> = asm
        .region_offsets
        .iter()
        .enumerate()
        .map(|(ri, &o)| {
            let end = asm
                .region_offsets
                .get(ri + 1)
                .copied()
                .unwrap_or(asm.lay.span);
            (o, end - o)
        })
        .collect();
    let region_transitions = wired.num_transition() - asm.n_groups;
    structure::emit(
        &asm,
        &off_heights,
        fri_log_blowup,
        log_dn,
        n_periodic,
        region_transitions,
        &periodic_root,
        &alloc::format!("{spec}/production-air-structure.json"),
    );

    // The deployment proof with the periodic sidecar: rate 1/16, 16 grind
    // bits = 128-bit conjectured, verified against the baked root.
    let wproof = stark_prove_ext_preprocessed(
        wired,
        &asm.witness,
        crate::shield_params::inner::N_QUERIES,
        crate::shield_params::inner::GRIND_BITS,
        crate::shield_params::inner::EXTRA_BLOWUP_BITS,
    )
    .expect("nothing watches this proof, so nothing can cancel it");
    assert!(
        stark_verify_ext_preprocessed(
            wired,
            &wproof,
            crate::shield_params::inner::N_QUERIES,
            crate::shield_params::inner::GRIND_BITS,
            crate::shield_params::inner::EXTRA_BLOWUP_BITS,
            &periodic_root
        ),
        "the production recursive vector does not verify"
    );

    vector::emit(
        &asm,
        &wproof,
        fri_log_blowup,
        &alloc::format!("{spec}/production-recursive-vector.json"),
    );
    intermediates::emit(
        &asm,
        &wproof,
        &alloc::format!("{spec}/reference/intermediates.json"),
    );
}
