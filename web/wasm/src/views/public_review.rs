use crate::json::Json;
use nox_shield_core::ffi::PublicReview;

pub fn public_review(r: &PublicReview) -> String {
    Json::obj()
        .num("id", r.id)
        .str("network", super::network(r.network))
        .str("coin", super::coin(r.coin))
        .opt("refusal", r.refusal.as_deref())
        .str("from", &r.from)
        .str("to", &r.to)
        .str("amount", &r.amount)
        .str("arrives", &r.arrives)
        .str("tokenFee", &r.token_fee)
        .str("tokenFeePercent", &r.token_fee_percent)
        .str("maxNetworkFee", &r.max_network_fee)
        .str("maxFeePerGasGwei", &r.max_fee_per_gas_gwei)
        .num("gasLimit", r.gas_limit)
        .num("nonce", r.nonce)
        .num("chainId", r.chain_id)
        .flag("toIsContract", r.to_is_contract)
        .flag("realMoney", r.real_money)
        .num("validForSeconds", r.valid_for_seconds)
        .done()
}
