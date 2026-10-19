//! Amounts and fees, which need no wallet.

use super::Answer;
use crate::json::text;
use crate::wallet::Args;
use nox_shield_core::ffi::{amount_unit, format_amount, max_note_amount, parse_amount};
use nox_shield_core::net::pool::ACTIVE;

pub fn call(method: &str, a: &Args) -> Answer {
    Some(match method {
        "formatAmount" => (|| Ok(format_amount(a.coin(0)?, a.number(1)?)))().map(|s| text(&s)),
        "parseAmount" => (|| parse_amount(a.coin(0)?, a.text(1)?))().map(|n| n.to_string()),
        "amountUnit" => a.coin(0).map(|c| text(&amount_unit(c))),
        "maxNoteAmount" => a.coin(0).map(|c| text(&max_note_amount(c))),
        // The relay fee in note units, printed as the apps print an amount.
        "relayFee" => a
            .coin(0)
            .map(|c| text(&format_amount(c, ACTIVE.asset(c).map_or(0, |asset| asset.relay_fee)))),
        "networkHasShield" => a.network(0).map(|n| n.chain().shield.to_string()),
        _ => return None,
    })
}
