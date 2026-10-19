use crate::json::Json;
use nox_shield_core::ffi::PublicBalances;

pub fn public_balances(b: &PublicBalances) -> String {
    Json::obj()
        .str("network", super::network(b.network))
        .str("address", &b.address)
        .str("eth", &b.eth)
        .str("nox", &b.nox)
        .str("usdc", &b.usdc)
        .done()
}
