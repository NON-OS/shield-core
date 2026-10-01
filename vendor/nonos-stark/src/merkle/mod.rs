// NONOS Operating System (AGPL-3.0-or-later)
//! Binary Merkle commitment over field-element leaves under keccak256, the
//! EVM's hash, kept to `DIGEST_BYTES`.
//! The prover commits and opens; the verifier calls `verify_path`.

mod hash;
pub mod multi;
mod top;
mod tree;
mod verify;

pub use hash::{hash_leaf_ext, hash_leaf_group, hash_leaf_quad, hash_leaf_wide, hash_leaf_wide_periodic, PeriodicLeafHasher, DIGEST_BYTES};
pub use top::TreeTop;
pub use tree::MerkleTree;
pub use verify::{verify_path, verify_path_ext, verify_path_group, verify_path_pair};
pub use verify::{verify_path_wide, verify_path_wide_periodic};
