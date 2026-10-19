//! Where a deposit lands, which every deposit blinding is bound to, so a blinding drawn for one
//! pool or chain never opens a note on another.

/// The chain id and the pool contract a deposit is sent to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DepositSite {
    pub chain_id: u64,
    pub pool: [u8; 20],
}
