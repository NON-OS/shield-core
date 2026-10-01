// NONOS Operating System (AGPL-3.0-or-later)

//! The money-grade DEEP STARK prover, streamed. The trace lives as coefficients
//! and every pass extends one coset at a time, so proving needs the memory of a
//! coset rather than of the evaluation domain. Byte-identical to the
//! materialized prover it replaced: same transcript order, same field values,
//! same trees.

mod commit;
mod compose;
mod coset;
mod deep;
mod entry;
mod frame;
mod ood;
mod queries;
mod run;
mod setup;

pub(in crate::air) use crate::poly::batch_inv;
pub(in crate::air) use commit::{trace_coeffs_cols, wide_streamed};
pub(in crate::air) use compose::{over_domain, BLOCK};
pub(in crate::air) use coset::{extend, periodic_coeffs, trace_coeffs};
pub(in crate::air) use deep::over_domain as deep_over_domain;
pub use entry::{stark_prove_ext, stark_prove_ext_blown, stark_prove_ext_blown_bound};
pub use entry::stark_prove_ext_zk;
pub(in crate::air) use frame::{comp_at_z, ood_frame, periodic_at_z};
pub(in crate::air) use ood::draw_ood_point_ext;
pub(in crate::air) use queries::eval_base;
pub(in crate::air) use setup::Domain;
pub use setup::SHIFT as COSET_SHIFT;
