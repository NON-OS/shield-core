// NONOS Operating System (AGPL-3.0-or-later)

//! The poseidon-transcript provers, streamed and pruned like everything else.
//! `trace` commits the columns, `queries` opens them, `sidecar` opens the
//! committed periodic rows; `pre` sequences the preprocessed protocol. What a
//! pass computes lives in one place; a prover is a transcript order.

mod pre;
mod queries;
mod rounds;
mod sidecar;
mod trace;

pub use pre::{stark_prove_poseidon_pre_pub, stark_prove_poseidon_pre_pub_watched};
pub use rounds::stark_prove_poseidon_pre_rounds;
pub(crate) use queries::open as open_query;
pub(crate) use trace::commit_wide;
