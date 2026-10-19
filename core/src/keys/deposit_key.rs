//! The key every deposit blinding of one account is drawn from. A blinding is a function of the
//! seed, the chain, the pool, the account and a deposit index, so the words alone find each
//! deposit again. The key wipes on drop and never crosses the FFI.

use super::deposit_site::DepositSite;
use super::derive::{byte_key, field_key};
use super::domain::{DEPOSIT_CONTEXT, DEPOSIT_KEY_CONTEXT};
use crate::error::CustodyError;
use zeroize::Zeroizing;

/// Bytes hashed for one blinding: the key, the chain id, the pool, the account, the index.
const INPUT: usize = 32 + 8 + 20 + 4 + 4;

/// One account's deposit key.
pub(crate) struct DepositKey {
    key: Zeroizing<[u8; 32]>,
    account: u32,
}

impl DepositKey {
    /// Derive the deposit key of account `account` from that account's key material.
    pub(crate) fn from_material(material: &[u8], account: u32) -> DepositKey {
        DepositKey { key: Zeroizing::new(byte_key(material, DEPOSIT_KEY_CONTEXT)), account }
    }

    /// The blinding of deposit `index` at `site`: four canonical field words, drawn by the
    /// prover's rejection sampler so no word reduces to another blinding.
    pub(crate) fn blinding(
        &self,
        site: &DepositSite,
        index: u32,
    ) -> Result<[u64; 4], CustodyError> {
        let mut input = Zeroizing::new(Vec::with_capacity(INPUT));
        input.extend_from_slice(self.key.as_slice());
        input.extend_from_slice(&site.chain_id.to_le_bytes());
        input.extend_from_slice(&site.pool);
        input.extend_from_slice(&self.account.to_le_bytes());
        input.extend_from_slice(&index.to_le_bytes());
        let words = field_key(&input, DEPOSIT_CONTEXT)?;
        Ok(words.map(|w| w.value()))
    }
}

impl core::fmt::Debug for DepositKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DepositKey(redacted)")
    }
}

#[cfg(test)]
#[path = "deposit_key_test.rs"]
mod deposit_key_test;
