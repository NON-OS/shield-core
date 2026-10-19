use crate::json::Json;
use nox_shield_core::ffi::format_amount;
use nox_shield_core::store::Balance;

/// A shielded balance, in note units and as the apps print it.
pub fn balance(b: &Balance) -> String {
    Json::obj()
        .str("coin", super::coin(b.coin))
        .num("spendable", b.spendable)
        .num("pending", b.pending)
        .num("noteCount", b.note_count)
        .str("spendableText", &format_amount(b.coin, b.spendable))
        .str("pendingText", &format_amount(b.coin, b.pending))
        .done()
}
