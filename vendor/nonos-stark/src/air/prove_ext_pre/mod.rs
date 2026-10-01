// NONOS Operating System (AGPL-3.0-or-later)

//! The preprocessed-periodic prover, streamed like `prove_ext` and sharing its
//! passes. What differs is the sidecar: the periodic tree is committed through
//! the registration helper, the periodic values at z ride the proof, and DEEP
//! carries one quotient per periodic column so the verifier can hold the
//! periodic root as a baked constant.

mod deep;
mod queries;
mod rounds;
mod run;

pub(in crate::air) use deep::over_domain as pre_deep_over_domain;
pub use rounds::{stark_prove_ext_rounds, stark_prove_ext_rounds_top, stark_prove_ext_rounds_top_observed};
pub use run::{stark_prove_ext_preprocessed, stark_prove_ext_preprocessed_tree};
pub use run::stark_prove_ext_preprocessed_watched;
