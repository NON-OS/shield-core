//! A public send between its review and the owner's yes.

/// A reviewed transaction, held as the screen described it.
pub(super) struct Pending {
    pub(super) id: u64,
    pub(super) network: crate::evm::Network,
    /// The account the review was worked out for.
    pub(super) from: [u8; 20],
    pub(super) tx: crate::evm::tx::Eip1559,
    pub(super) made: std::time::Instant,
    /// For a deposit, the index its blinding was drawn at and the note it creates, both stored
    /// before the deposit leaves.
    pub(super) note: Option<HeldDeposit>,
}

/// A reviewed deposit's index and note, and the draw that reserved the index.
pub(super) struct HeldDeposit {
    pub(super) index: u32,
    pub(super) note: crate::notes::NotePlaintext,
    pub(super) stamp: u64,
    pub(super) draw: u64,
}
