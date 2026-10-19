use crate::json::{list, Json};
use nox_shield_core::ffi::ChainSummary;

/// What a read of the pool found, with the wait the privacy meter counts down.
pub fn chain_summary(c: &ChainSummary) -> String {
    Json::obj()
        .num("head", c.head)
        .num("received", c.received)
        .num("deposited", c.deposited)
        .num("spent", c.spent)
        .raw("balances", &list(c.balances.iter().map(super::balance)))
        .num("waitLeaves", c.wait_leaves)
        .num("waitMinutes", c.wait_minutes)
        .done()
}
