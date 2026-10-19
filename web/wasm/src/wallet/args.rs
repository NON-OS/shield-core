//! The arguments a call carries from the page, all strings, read into the core's types.

use nox_shield_core::error::WalletError;
use nox_shield_core::evm::Network;
use nox_shield_core::net::asset::Coin;

pub struct Args<'a> {
    values: &'a [String],
}

impl<'a> Args<'a> {
    pub fn of(values: &'a [String]) -> Args<'a> {
        Args { values }
    }

    pub fn text(&self, at: usize) -> Result<String, WalletError> {
        self.values.get(at).cloned().ok_or(WalletError::Amount)
    }

    pub fn number(&self, at: usize) -> Result<u64, WalletError> {
        self.text(at)?.parse().map_err(|_| WalletError::Amount)
    }

    pub fn index(&self, at: usize) -> Result<u32, WalletError> {
        u32::try_from(self.number(at)?).map_err(|_| WalletError::NoSuchAccount)
    }

    pub fn flag(&self, at: usize) -> Result<bool, WalletError> {
        Ok(self.text(at)? == "true")
    }

    pub fn coin(&self, at: usize) -> Result<Coin, WalletError> {
        match self.text(at)?.as_str() {
            "eth" => Ok(Coin::Eth),
            "nox" => Ok(Coin::Nox),
            "usdc" => Ok(Coin::Usdc),
            _ => Err(WalletError::Amount),
        }
    }

    pub fn network(&self, at: usize) -> Result<Network, WalletError> {
        match self.text(at)?.as_str() {
            "mainnet" => Ok(Network::Mainnet),
            "sepolia" => Ok(Network::Sepolia),
            _ => Err(WalletError::Unavailable),
        }
    }

    /// Every argument from `from` on, for the recovery words.
    pub fn rest(&self, from: usize) -> Vec<String> {
        self.values.get(from..).map(<[String]>::to_vec).unwrap_or_default()
    }
}
