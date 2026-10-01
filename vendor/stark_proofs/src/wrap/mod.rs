// NONOS Operating System (AGPL-3.0-or-later)

//! The wrap: the settlement outer verified inside a circuit narrow enough
//! for one transaction. Its pieces, by name.

mod outer;
mod rec;

pub use outer::{packed_outer, packed_outer_at, typed_outer, OuterInner, OuterPoint};
pub use rec::{Op, Rec, Recorded, Tape};
