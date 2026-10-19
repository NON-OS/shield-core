use crate::json::Json;
use nox_shield_core::ffi::PublicSwap;

/// A swap under review: what goes in and out, the quote's terms and the route through the pools.
pub fn public_swap(s: &PublicSwap) -> String {
    Json::obj()
        .num("id", s.id)
        .str("network", super::network(s.network))
        .str("from", super::coin(s.from))
        .str("to", super::coin(s.to))
        .opt("refusal", s.refusal.as_deref())
        .flag("approval", s.approval)
        .str("amountIn", &s.amount_in)
        .str("expectedOut", &s.expected_out)
        .str("minimumOut", &s.minimum_out)
        .str("tokenFee", &s.token_fee)
        .str("priceImpactPercent", &s.price_impact_percent)
        .str("slippagePercent", &s.slippage_percent)
        .str("route", &s.route)
        .str("rate", &s.rate)
        .str("venue", &s.venue)
        .strs("pools", &s.pools)
        .str("poolFeePercent", &s.pool_fee_percent)
        .str("maxNetworkFee", &s.max_network_fee)
        .str("maxFeePerGasGwei", &s.max_fee_per_gas_gwei)
        .num("gasLimit", s.gas_limit)
        .num("nonce", s.nonce)
        .num("chainId", s.chain_id)
        .flag("realMoney", s.real_money)
        .num("validForSeconds", s.valid_for_seconds)
        .done()
}
