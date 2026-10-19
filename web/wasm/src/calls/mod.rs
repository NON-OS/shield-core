//! The wallet's calls, one group per screen area. Each group answers the methods it knows and
//! passes on the rest, so the dispatcher is a list of groups and nothing more.

mod accounts;
mod amounts;
mod lifecycle;
mod pool;
mod public;
mod shield;
mod spend;

use crate::wallet::Args;
use nox_shield_core::error::WalletError;
use nox_shield_core::ffi::Wallet;

pub type Answer = Option<Result<String, WalletError>>;

/// Run `method` on `wallet`, or none when no group knows it.
pub fn dispatch(wallet: &Wallet, method: &str, args: &Args) -> Answer {
    lifecycle::call(wallet, method, args)
        .or_else(|| accounts::call(wallet, method, args))
        .or_else(|| public::call(wallet, method, args))
        .or_else(|| shield::call(wallet, method, args))
        .or_else(|| pool::call(wallet, method, args))
        .or_else(|| spend::call(wallet, method, args))
        .or_else(|| amounts::call(method, args))
}
