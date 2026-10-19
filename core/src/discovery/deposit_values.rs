//! The values a deposit note can hold. A deposit is a standard size of a pool asset, less the
//! pool's rounded down fee, so the whole set is public and small, and a restore tries each one
//! instead of asking any server what was deposited.

use crate::net::asset::Asset;
use crate::wallet::deposit_split::sizes;
use crate::wallet::split_deposit;
use std::collections::BTreeSet;

/// The highest deposit fee tried, in basis points. The pool keeps 50 today, and twice that
/// leaves room for a policy change without a new build.
pub const MOST_DEPOSIT_FEE_BPS: u16 = 100;

/// Every `(asset id, note value)` a deposit of `assets` can make, each once.
pub(crate) fn deposit_values(assets: &[Asset]) -> Vec<(u64, u64)> {
    let mut out = BTreeSet::new();
    for asset in assets {
        for size in sizes(asset) {
            for fee_bps in 0..=MOST_DEPOSIT_FEE_BPS {
                if let Some((_, value)) = split_deposit(size, fee_bps) {
                    out.insert((asset.id, value));
                }
            }
        }
    }
    out.into_iter().collect()
}
