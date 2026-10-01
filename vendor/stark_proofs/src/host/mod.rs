// NONOS Operating System (AGPL-3.0-or-later)

//! What the host tools share: the request as the operator states it, the
//! spend built and refused from it, and the outer proved and written.

mod outer;
mod request;
mod spend;

pub use outer::{point_from_args, prove_outer, prove_outer_as, Point, Settled, Verdict};
pub use request::{address, die, os_words, pack_u256, quad, read_text, try_address, Entropy, Json};
pub use request::{try_unpack_digest, unpack_digest};
pub use spend::{build_batch, build_parts, build_parts_with, build_spend, Built, Created, Parts};
