use crate::json::{list, Json};
use nox_shield_core::ffi::WatchedSummary;
use nox_shield_core::keys::ViewKind;

/// An account shared by its view key: it shows notes and never sends.
pub fn watched_summary(w: &WatchedSummary) -> String {
    let kind = match w.kind {
        ViewKind::Incoming => "incoming",
        ViewKind::Full => "full",
    };
    Json::obj()
        .num("index", w.index)
        .str("kind", kind)
        .raw("balances", &list(w.balances.iter().map(super::balance)))
        .done()
}
