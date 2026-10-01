// NONOS Operating System (AGPL-3.0-or-later)

//! A Merkle commitment whose node hash is the Poseidon permutation rather than
//! BLAKE3. Its point is not speed but arithmetization: every node is a fixed
//! sequence of field operations, so a path check can be expressed as AIR
//! constraints and proven inside another STARK. That is the commitment a
//! recursive verifier needs, since a bitwise hash like BLAKE3 cannot be proven
//! cheaply. Digests are `RATE` field elements; leaves are already digests.

mod pack_base;
mod pruned;
mod pack_ext;
mod tree;
mod verify;

pub use pack_base::pack_base;
pub use pruned::PrunedPoseidonTree;
pub use pack_ext::{pack_ext, pack_pair_ext, pair_at, pair_partner};
pub use tree::PoseidonMerkleTree;
pub use verify::verify_path;
