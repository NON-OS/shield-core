//! The chain and pool every deposit of this build is bound to.

use crate::error::WalletError;
use crate::ffi::evm::parse_evm_address;
use crate::keys::DepositSite;
use crate::net::pool::{ACTIVE, CHAIN_ID};

/// The active pool on its chain.
pub(super) fn active_site() -> Result<DepositSite, WalletError> {
    Ok(DepositSite { chain_id: CHAIN_ID, pool: parse_evm_address(ACTIVE.address)? })
}
