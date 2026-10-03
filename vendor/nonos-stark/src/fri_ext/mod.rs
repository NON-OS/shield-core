// NONOS Operating System (AGPL-3.0-or-later)

//! The money-grade FRI low-degree test: identical in structure to `fri`, but the
//! fold challenges are drawn from the degree-2 extension `Fp2` and a proof-of-work
//! nonce is ground before the queries. Extension challenges take the folding
//! soundness error from ~2^-64 to ~2^-128, and grinding raises the query
//! soundness. This is the FRI a high-value proof uses; the base `fri` module
//! remains for the recursive-verifier arithmetization.

pub mod deep_leaf;
mod grind;
mod prove;
mod types;
mod verify;

pub use grind::{
    shape_accepts, shape_id, ATTEST_SHAPE, COMMIT_GRIND_BITS, DEEP_GRIND_BITS, GRIND_CHUNKS, QUERY_SHAPES,
};
pub use prove::{fri_prove_ext, fri_prove_ext_layer_zero, fri_prove_ext_layer_zero_ground};
pub use types::{FriProofExt, LayerOpeningExt, QueryProofExt};
pub use verify::{fri_final_vector_ext, fri_fold_challenges_ext, fri_positions_ext};
pub use verify::{fri_verify_ext, fri_verify_ext_seeded, fri_verify_ext_seeded_ground};
