//! The checks that turn a reading into a refusal, each in one sentence a
//! screen can show as it is.

use super::network::Chain;
use super::nox::READS;
use super::nox_revert::why;
use super::nox_rules::{outcome, Outcome};
use super::reply::Answer;
use super::review_parts::{Arrival, Order};
use crate::error::NetError;
use crate::net::asset::Coin;

/// The answers every send reads, in order, before the token's.
pub(super) const COMMON: usize = 6;

/// Refusals that need no reading: nothing, nowhere, or somewhere that keeps it.
pub(super) fn before_reading(
    chain: &Chain,
    from: &[u8; 20],
    order: &Order,
) -> Option<&'static str> {
    if order.amount == 0 {
        return Some("Enter an amount above zero.");
    }
    if order.to == [0u8; 20] {
        return Some("That is the zero address. Anything sent there is lost.");
    }
    if &order.to == from {
        return Some("That is this account's own address.");
    }
    if order.to == chain.nox_token || order.to == chain.usdc_token {
        return Some("That is a token contract itself. Anything sent there is lost.");
    }
    None
}

/// What a NOX transfer delivers, or why it would not happen.
pub(super) fn nox_arrival(
    chain: &Chain,
    token: &[Answer],
    held: u128,
    amount: u128,
) -> Result<Result<Arrival, &'static str>, NetError> {
    if token.len() != READS {
        return Err(NetError::ReplyShape);
    }
    let Some(rules) = super::nox_read::rules(chain, token)? else {
        return Ok(Err(
            "NOX's contract changed after this app was built. Update the app to send NOX.",
        ));
    };
    if held < amount {
        return Ok(Err("The NOX balance does not cover that."));
    }
    if let Some(Answer::Reverted(data)) = token.last() {
        return Ok(Err(why(data)));
    }
    Ok(match outcome(&rules, amount) {
        Outcome::Arrives { amount, fee, bps } => Ok(Arrival { arrives: amount, fee, bps }),
        Outcome::Refused(why) => Err(why),
    })
}

/// The gas limit, or why the send stops: the node gave no estimate, which is
/// how it says the transfer would fail, or one past what such a send takes.
/// Ether to a person fails an estimate only when the node cannot price it, so
/// that one is worth another try.
pub(super) fn gas_limit(estimate: &Answer, plain: bool) -> Result<u64, &'static str> {
    let Ok(asked) = estimate.quantity() else {
        return Err(if plain {
            "The network could not price this transfer. Nothing was sent; try again."
        } else {
            "The network refused this transfer when it was tried."
        });
    };
    super::gas::limit(asked, plain).ok_or(
        "A server asked for far more gas than this transfer takes. Nothing was sent; try again.",
    )
}

/// Whether an ether send asks for more than the account holds, checked before
/// the gas, so that refusal names the balance.
pub(super) fn ether_short(order: &Order, ether: u128) -> Option<&'static str> {
    (order.coin == Coin::Eth && ether < order.amount)
        .then_some("The ETH balance does not cover that.")
}

/// Whether the ether on hand covers what the send takes of it.
pub(super) fn afford(order: &Order, ether: u128, max_fee: u128) -> Option<&'static str> {
    match order.coin {
        Coin::Eth if !nox_verified::fee::covers(ether, order.amount, max_fee) => {
            Some("The ETH balance does not cover the amount and the most the network fee can be.")
        }
        Coin::Nox | Coin::Usdc if ether < max_fee => {
            Some("This account needs ETH to pay the network fee.")
        }
        _ => None,
    }
}

/// Whether two servers' answers give the token the same implementation and
/// the same rules for this transfer.
pub(super) fn token_agrees(
    chain: &Chain,
    first: &[Answer],
    second: &[Answer],
) -> Result<bool, NetError> {
    let span = |a: &[Answer]| -> Result<_, NetError> {
        let end = COMMON.checked_add(READS).ok_or(NetError::ReplyShape)?;
        let token = a.get(COMMON..end).ok_or(NetError::ReplyShape)?;
        super::nox_read::rules(chain, token)
    };
    Ok(span(first)? == span(second)?)
}

#[cfg(kani)]
#[path = "review_checks_kani.rs"]
mod review_checks_kani;

/// What a USDC transfer delivers, which is all of it, or why Circle's
/// contract would refuse it, from a transfer simulated as the sender.
pub(super) fn usdc_arrival(
    simulated: &Answer,
    held: u128,
    amount: u128,
) -> Result<Arrival, &'static str> {
    if held < amount {
        return Err("The USDC balance does not cover that.");
    }
    match simulated {
        Answer::Result(_) => Ok(Arrival { arrives: amount, fee: 0, bps: 0 }),
        Answer::Reverted(data) => Err(super::usdc_revert::why(data)),
        Answer::Failed => Err("USDC refused this transfer when it was tried."),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::super::reply::one;
    use super::*;

    #[test]
    fn ether_to_a_person_takes_the_estimate_and_stops_without_one() {
        let fresh = one(r#"{"id":1,"result":"0x32a1f"}"#).unwrap();
        assert_eq!(gas_limit(&fresh, true), Ok(228_130));
        assert!(gas_limit(&Answer::Failed, true).unwrap_err().contains("try again"));
        assert!(gas_limit(&Answer::Reverted(Vec::new()), true).is_err());
        assert!(gas_limit(&Answer::Failed, false).unwrap_err().contains("refused"));
    }

    #[test]
    fn a_hostile_estimate_is_refused_before_it_sets_the_fee() {
        let greedy = one(r#"{"id":1,"result":"0x2faf080"}"#).unwrap();
        assert!(gas_limit(&greedy, true).unwrap_err().contains("far more gas"));
    }

    #[test]
    fn more_ether_than_held_names_the_balance() {
        let order = Order { coin: Coin::Eth, to: [1u8; 20], amount: 10 };
        assert_eq!(ether_short(&order, 9), Some("The ETH balance does not cover that."));
        assert_eq!(ether_short(&order, 10), None);
        assert_eq!(ether_short(&Order { coin: Coin::Nox, ..order }, 0), None);
    }
}
