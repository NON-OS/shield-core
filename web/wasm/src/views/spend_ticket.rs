use crate::json::Json;
use nox_shield_core::ffi::SpendTicket;

/// A proved spend. The hand-off files stay in the wallet's own storage; the page needs only to
/// know they were written and which anonymity defaults were given up.
pub fn spend_ticket(t: &SpendTicket) -> String {
    Json::obj()
        .num("files", u64::try_from(t.handoff_files.len()).unwrap_or(0))
        .strs("weakened", &t.weakened)
        .done()
}
