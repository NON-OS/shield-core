//! The most of one coin a send or a swap can spend, as the Max button fills
//! it in: every unit of a token, and for ether the balance less the most the
//! network fee of a swap or of a transfer that creates an account can be, with
//! room for the fee to rise before the send is reviewed.

use super::calls::{balance, call, estimate, latest_block, priority_fee};
use super::network::Network;
use super::nox::{with_address, BALANCE_OF};
use super::rpc::ask;
use crate::error::NetError;
use crate::net::asset::Coin;
use crate::net::tor::Tor;

/// Gas kept back for a swap: above the most a two-hop swap was measured to
/// use on mainnet, 221,000.
const SWAP_GAS: u128 = 300_000;

/// The reserve is priced at half again the latest fee ceiling, so a few blocks
/// of a rising base fee do not leave a Max send short.
const FEE_ROOM_NUM: u128 = 3;
const FEE_ROOM_DEN: u128 = 2;

pub fn max_spend(tor: &Tor, network: Network, of: &[u8; 20], coin: Coin) -> Result<u128, NetError> {
    let chain = network.chain();
    let mut calls = vec![balance(of), latest_block(), priority_fee()];
    match chain.token(coin) {
        Some(token) => calls.push(call(None, &token, &with_address(BALANCE_OF, of))),
        // A transfer of one wei to an address drawn here, so the estimate is
        // what a send to an account that does not exist yet would take.
        None => calls.push(estimate(of, &unused_address()?, 1, &[])),
    }
    let answers = ask(tor, &chain, &calls)?;
    let at = |i: usize| answers.get(i).ok_or(NetError::ReplyShape);
    if chain.token(coin).is_some() {
        return at(3)?.word();
    }
    let ether = at(0)?.quantity()?;
    let fee = super::gas::fees(at(1)?, at(2)?)?.map_or(u128::MAX, |f| f.max_fee);
    let transfer = at(3)?
        .quantity()
        .ok()
        .and_then(|e| super::gas::limit(e, true))
        .map_or(super::gas::ETHER_CEILING, u128::from);
    let room = fee.saturating_mul(FEE_ROOM_NUM).checked_div(FEE_ROOM_DEN).unwrap_or(u128::MAX);
    Ok(ether.saturating_sub(SWAP_GAS.max(transfer).saturating_mul(room)))
}

fn unused_address() -> Result<[u8; 20], NetError> {
    let mut a = [0u8; 20];
    crate::entropy::fill(&mut a).map_err(|_| NetError::Transport)?;
    Ok(a)
}
