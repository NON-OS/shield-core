//! The local store, whose file a seized or tampered device does not protect.

use crate::store::{frame, row};

/// One length prefixed frame from the front of the note log.
pub fn frame(bytes: &[u8]) {
    let _ = frame::decode(bytes);
}

/// One row payload, after its frame has been opened.
pub fn row(bytes: &[u8]) {
    let _ = row::decode::decode(bytes);
}
