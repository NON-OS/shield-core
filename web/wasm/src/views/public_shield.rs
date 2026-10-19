use crate::json::Json;
use nox_shield_core::ffi::PublicShield;

/// A deposit, an approval or a settlement under review.
pub fn public_shield(s: &PublicShield) -> String {
    Json::obj()
        .num("id", s.id)
        .opt("refusal", s.refusal.as_deref())
        .flag("approval", s.approval)
        .str("amount", &s.amount)
        .str("poolFee", &s.pool_fee)
        .str("shielded", &s.shielded)
        .str("maxNetworkFee", &s.max_network_fee)
        .num("validForSeconds", s.valid_for_seconds)
        .done()
}
