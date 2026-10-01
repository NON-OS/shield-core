// NONOS Operating System (AGPL-3.0-or-later)

//! The FRI low-degree test: a transparent, post-quantum argument that a
//! committed codeword is close to a low-degree polynomial. It is the engine a
//! STARK uses to check the trace and its constraints without a trusted setup.

mod domain;
mod fold;
#[cfg(test)]
mod fold_test;
mod prove;
mod stop;
mod types;
mod verify;

pub use domain::root_of_unity;
pub use fold::{fold_ext, fold_first, fold_layer};
pub use prove::fri_prove;
pub use stop::{final_coefficients, final_log, final_point, horner, n_folds, n_layers};
pub use stop::{stop_log, FOLD, FRI_FOLD_LOG, FRI_STOP_LOG};
pub use types::{FriProof, LayerOpening, QueryProof};
pub use verify::fri_verify;
