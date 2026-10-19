use crate::json::Json;
use nox_shield_core::ffi::DepositTicket;

/// A deposit to send from another wallet: what to send, and where.
pub fn deposit_ticket(t: &DepositTicket) -> String {
    Json::obj()
        .opt("refusal", t.refusal.as_deref())
        .str("amount", &t.amount)
        .str("fee", &t.fee)
        .str("note", &t.note)
        .str("approveTo", &t.approve_to)
        .str("approveData", &t.approve_data)
        .str("depositTo", &t.deposit_to)
        .str("depositData", &t.deposit_data)
        .str("valueWei", &t.value_wei)
        .done()
}
