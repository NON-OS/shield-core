//! The network fee a send offers, from the latest block.
//! EIP-1559: the tip is the RPC's suggestion held to 5 gwei, so a lying RPC
//! cannot talk a send into overpaying. The ceiling is twice the latest base fee
//! plus the tip, and a ceiling past 1,000 gwei is refused, whatever the RPC said.

use super::reply::Answer;
use crate::error::NetError;
use crate::net::rpc::{after, quoted};

#[cfg(kani)]
use nox_verified::fee::{CEILING, MAX_TIP};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct Fees {
    pub max_priority_fee: u128,
    pub max_fee: u128,
}

/// The fees from the answers to the latest block and the suggested tip, or
/// none when the ceiling would pass `CEILING`.
pub(super) fn fees(block: &Answer, tip: &Answer) -> Result<Option<Fees>, NetError> {
    Ok(offer(base_fee(block.result()?)?, tip.quantity()?))
}

/// The offer for a base fee and a suggested tip, from the verified kernel,
/// with the bounds proved in Lean.
pub(super) fn offer(base: u128, suggested: u128) -> Option<Fees> {
    nox_verified::fee::offer(base, suggested)
        .map(|(tip, max_fee)| Fees { max_priority_fee: tip, max_fee })
}

/// The latest block's time, in seconds, for a swap's deadline.
pub(super) fn timestamp(block: &Answer) -> Result<u64, NetError> {
    let text = block.result()?;
    let hex = after(text, "\"timestamp\"").and_then(quoted).ok_or(NetError::ReplyShape)?;
    let body = hex.strip_prefix("0x").ok_or(NetError::ReplyShape)?;
    u64::from_str_radix(body, 16).map_err(|_| NetError::ReplyShape)
}

pub(super) fn base_fee(block: &str) -> Result<u128, NetError> {
    let hex = after(block, "\"baseFeePerGas\"").and_then(quoted).ok_or(NetError::ReplyShape)?;
    let body = hex.strip_prefix("0x").ok_or(NetError::ReplyShape)?;
    u128::from_str_radix(body, 16).map_err(|_| NetError::ReplyShape)
}

/// The least gas any transaction takes.
pub(super) const FLOOR: u128 = 21_000;

/// The most a plain ether transfer adds to its estimate.
pub(super) const ETHER_MARGIN: u128 = 21_000;

/// The gas limit from the node's estimate. Ether to an address with no code
/// gets a tenth on top, at most `ETHER_MARGIN` and never under `FLOOR`: a
/// fixed 21,000 fails where a transfer that creates an account costs more.
/// Anything else gets a quarter on top, since a token transfer's cost can move.
pub(super) fn limit(estimate: u128, plain_ether: bool) -> Option<u64> {
    let padded = if plain_ether {
        let margin = estimate.checked_div(10)?.min(ETHER_MARGIN);
        estimate.checked_add(margin)?.max(FLOOR)
    } else {
        estimate.checked_mul(5)?.checked_div(4)?
    };
    u64::try_from(padded).ok()
}

#[cfg(kani)]
#[path = "gas_kani.rs"]
mod gas_kani;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::super::reply::one;
    use super::*;

    #[test]
    fn the_ceiling_is_twice_the_base_fee_plus_the_tip() {
        let block =
            one(r#"{"id":1,"result":{"baseFeePerGas":"0x3b9aca00","number":"0x1"}}"#).unwrap();
        let tip = one(r#"{"id":2,"result":"0x5f5e100"}"#).unwrap();
        let f = fees(&block, &tip).unwrap().unwrap();
        assert_eq!(f, Fees { max_priority_fee: 100_000_000, max_fee: 2_100_000_000 });
    }

    #[test]
    fn an_absurd_fee_is_refused() {
        let block = one(r#"{"id":1,"result":{"baseFeePerGas":"0xe8d4a51000"}}"#).unwrap();
        let tip = one(r#"{"id":2,"result":"0x1"}"#).unwrap();
        assert_eq!(fees(&block, &tip).unwrap(), None);
        let calm = one(r#"{"id":1,"result":{"baseFeePerGas":"0x1"}}"#).unwrap();
        let greedy = one(r#"{"id":2,"result":"0x2540be400"}"#).unwrap();
        assert_eq!(fees(&calm, &greedy).unwrap().unwrap().max_priority_fee, 5_000_000_000);
        assert_eq!(limit(40_000, false), Some(50_000));
    }

    // Sepolia's estimates for 0.01 ETH to an account that did not exist yet,
    // where 21,000 ran out of gas on chain, and to one that did.
    #[test]
    fn ether_to_a_fresh_account_gets_what_the_node_asked_for_and_a_tenth() {
        assert_eq!(limit(207_391, true), Some(228_130));
    }

    #[test]
    fn ether_to_an_existing_account_never_gets_less_than_21000() {
        assert_eq!(limit(12_000, true), Some(21_000));
        assert_eq!(limit(21_000, true), Some(23_100));
    }

    #[test]
    fn the_margin_on_ether_stops_at_21000() {
        assert_eq!(limit(1_000_000, true), Some(1_021_000));
    }
}
