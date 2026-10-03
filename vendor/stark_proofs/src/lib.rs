// NONOS Operating System (AGPL-3.0-or-later)
//! Host-runnable proofs for the STARK verification primitives. Includes the
//! real src/crypto source and checks it against its specification.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod activity;
pub mod attest;
pub mod budget;
#[cfg(feature = "std")]
pub mod compose_pipeline;
pub mod crypto;
mod deployed;
#[cfg(feature = "std")]
pub mod host;
pub mod lean_schedule;
pub mod lean_text;
pub mod proof_wire;
pub mod recursion_assembly;
#[cfg(feature = "std")]
pub mod root_cache;
pub mod shield;
pub mod shield_params;
#[cfg(feature = "std")]
pub mod tree_cache;
mod witness_satisfies;
#[cfg(feature = "std")]
pub mod wrap;
pub mod zk_rank;

pub use deployed::{shield_deployed_wired, witness_satisfies_public};

#[cfg(test)]
mod air_tests;
#[cfg(test)]
mod batch_shape_tests;
#[cfg(test)]
mod cell_audit_test;
#[cfg(test)]
mod checkpoint_lean_test;
#[cfg(test)]
mod checkpoint_test;
#[cfg(test)]
mod compose_pipeline_tests;
#[cfg(test)]
mod deep_tie_tests;
#[cfg(test)]
mod dims_groups_tests;
#[cfg(test)]
mod dims_kind_tests;
#[cfg(test)]
mod dims_recursion_tests;
#[cfg(test)]
mod dims_transfer_tests;
#[cfg(test)]
mod family_tests;
#[cfg(test)]
mod fold_witness_tests;
#[cfg(test)]
mod fri_ext_tests;
#[cfg(test)]
mod fri_poseidon_ext_tests;
#[cfg(test)]
mod fri_tests;
#[cfg(test)]
mod grind_kat_test;
#[cfg(test)]
mod merkle_tests;
#[cfg(test)]
mod overlay_test;
#[cfg(test)]
mod parallel_bytes_tests;
#[cfg(test)]
mod periodic_classes_test;
#[cfg(test)]
mod periodic_z_tests;
#[cfg(test)]
mod periodic_zero_tests;
#[cfg(test)]
mod pin_half_tests;
#[cfg(test)]
mod poseidon_constants_gen;
#[cfg(test)]
mod poseidon_outer_tests;
#[cfg(test)]
mod poseidon_pre_tests;
#[cfg(test)]
mod preprocessed_tests;
#[cfg(test)]
mod production_vector_gen;
#[cfg(test)]
mod rate_bench_test;
#[cfg(test)]
mod recursion_assembly_tests;
#[cfg(test)]
mod recursion_cost_tests;
#[cfg(test)]
mod relay_tests;
#[cfg(test)]
mod seam2_tests;
#[cfg(test)]
mod shield_free_cells_tests;
#[cfg(test)]
mod spec_out;
#[cfg(test)]
mod stark_selftest_gen;
#[cfg(test)]
mod vk_stability_tests;
#[cfg(test)]
mod wired_chained_tests;
#[cfg(test)]
mod wired_rounds_tests;
#[cfg(test)]
mod wrap_eval_tests;
#[cfg(test)]
mod wrap_gen_tests;
#[cfg(test)]
mod wrap_prove_tests;
#[cfg(test)]
mod wrap_rec_tests;

#[cfg(kani)]
mod kani_proofs;
