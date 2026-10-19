use crate::json::Json;
use nox_shield_core::ffi::AccountSummary;

pub fn account_summary(a: &AccountSummary) -> String {
    Json::obj()
        .num("index", a.index)
        .str("publicAddress", &a.public_address)
        .flag("active", a.active)
        .done()
}
