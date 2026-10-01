// NONOS Operating System (AGPL-3.0-or-later)
//! A spend proved on the user's own device.
//!
//! One call, `prove(request, seed, entropy)`, from the pool's request and the
//! owner's seed file to the proof the chain verifies directly, at the launch
//! point (`shield_params::direct`). Nothing here touches a file, a clock or the
//! network, and nothing ends the process: the caller supplies the randomness,
//! and every refusal comes back as an error naming what was wrong. The same
//! code serves a browser through `wasm`, a phone or desktop app through the C
//! functions in `ffi`, and the command line through `nox_bench`.
//!
//! The proof is verified here before it is returned, so a caller never holds
//! bytes the chain would refuse.

pub mod api;
#[cfg(test)]
mod error_code_test;
mod ffi;
pub mod hedge;
pub mod policy;
#[cfg(test)]
mod profile_test;
mod proof;
#[cfg(test)]
mod rank_vectors_test;
#[cfg(test)]
mod shared_test;
#[cfg(all(feature = "wasm-threads", target_arch = "wasm32"))]
mod thread_cache;
#[cfg(test)]
mod v2_emit_test;
#[cfg(test)]
mod v2_review_test;
#[cfg(feature = "wasm")]
mod wasm;

pub use api::{
    load_cache, prove_with, verify, zk_fri_rank_check, Error, Options, Phase, PERIODIC_ROOT,
};
pub use api::{to_shared, verify_shared};
pub use proof::{prove, prove_keeping_cache, prove_with_cache, to_json, Proof, Rank};
pub use proof::{ENTROPY_BYTES, GRIND_BITS, PERIODIC_CUT};
