// NONOS Operating System (AGPL-3.0-or-later)

//! FRI committed with Poseidon instead of BLAKE3. The commitments and the
//! transcript are algebraic, so a proof made here can be verified by an AIR:
//! the prerequisite for a recursive STARK. It is otherwise the same protocol.

mod fold;
mod prove;
mod types;
mod verify;

pub use prove::fri_prove;
pub use types::{FriProof, LayerOpening, QueryProof};
pub use verify::fri_verify;
