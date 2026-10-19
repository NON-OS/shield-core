//! One row of the store, and the two directions it travels. An unknown kind is refused, since
//! reading around it could make a spent note spendable again.

// Crate visible so the fuzz surface can hand it a row payload directly.
pub(crate) mod decode;
mod encode;
mod status;

use crate::notes::{NoteKey, NoteRecord, NoteStatus};

pub(super) const FOUND: u8 = 1;
pub(super) const STATUS: u8 = 2;
pub(super) const CURSOR: u8 = 3;
/// A deposit sent and not yet seen stored: the opening, which exists nowhere
/// else until the pool stores its leaf. A new kind, so older stores still read.
pub(super) const DEPOSIT: u8 = 4;
/// A deposit index drawn for a deposit about to be kept, so no later deposit draws it again.
pub(super) const DEPOSIT_INDEX: u8 = 5;
/// A note's status moved, naming its leaf as well as its commitment, since two notes can share a
/// commitment. Kind 2 named the commitment alone and still reads, for every note under it.
pub(super) const STATUS_AT: u8 = 6;

/// What one row says.
pub enum Row {
    /// A note this wallet opened, with the position the pool gave it.
    Found(NoteRecord),
    /// A note's status moved: the note at `leaf`, or with no leaf, as an older store wrote it,
    /// every note held under `cm`.
    Status { cm: [u64; 4], leaf: Option<u64>, status: NoteStatus },
    /// The scan reached this output index.
    Cursor(u64),
    /// A deposit this wallet built and sent, not yet seen in the pool. Its
    /// opening is the only copy of the note's secret until the leaf is stored.
    Deposit(crate::notes::NotePlaintext),
    /// The deposit index whose blinding a kept deposit uses. Written before the deposit, so a
    /// crash between the two wastes an index and never reuses one.
    DepositIndex(u32),
}

pub use decode::decode;

impl Row {
    /// The status of the one note at `key`.
    pub fn status(key: NoteKey, status: NoteStatus) -> Row {
        let (cm, leaf) = key;
        Row::Status { cm, leaf: Some(leaf), status }
    }
}
