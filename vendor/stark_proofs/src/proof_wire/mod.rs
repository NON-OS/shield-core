// NONOS Operating System (AGPL-3.0-or-later)

//! The wire layouts a proof travels in. Two transcripts, so two codecs: keccak
//! for the outer a chain verifies, Poseidon for the inner a recursion folds and
//! a wallet hands to a relayer.

mod ext;
mod header;
mod layout;
mod poseidon;
mod poseidon_rounds;
#[cfg(test)]
mod poseidon_test;
mod read;
mod read_rounds;
mod shared;
mod write;

pub use ext::{serialize_pre, serialize_rounds, ROUNDS_HEADER};
pub use header::{check_header, read_header, write_header, Header, ParamSet};
pub use header::{
    FORMAT_SHARED, FORMAT_SHARED_BUILD, FORMAT_7, FORMAT_VERSION, HEADER_BYTES, MAGIC,
    PROTOCOL_VERSION,
};
pub use layout::{FriLayer, Layout, Manifest, Section, LAYOUT_DOMAIN};
pub use poseidon::{deserialize_p_pre, serialize_p_pre};
pub use poseidon_rounds::{deserialize_p_rounds, serialize_p_rounds, P_ROUNDS_HEADER};
pub use read_rounds::{deserialize_rounds, deserialize_rounds_legacy};
pub use shared::{deserialize_rounds_shared, serialize_rounds_shared};
