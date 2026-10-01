// NONOS Operating System (AGPL-3.0-or-later)

//! Poseidon-committed money-grade FRI over the degree-2 extension. Same soundness
//! as the keccak `fri_ext` (extension challenges, grinding), but committed with
//! Poseidon so the entire low-degree test is cheap to re-verify inside a STARK.
//! This is the inner form a recursive verifier folds over; the keccak form is the
//! outer form an on-chain verifier checks.

mod prove;
mod types;
mod verify;

pub use prove::{fri_prove_poseidon_ext, fri_prove_poseidon_ext_seeded};
pub use types::{FriProofExtP, LayerOpeningExtP, QueryProofExtP};
pub use verify::{fri_positions_poseidon, fri_verify_poseidon_ext, fri_verify_poseidon_ext_seeded};
