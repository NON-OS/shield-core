//! Private sends and withdrawals, proved here in the page.

use super::Answer;
use crate::json::{text, Json};
use crate::views::spend_ticket;
use crate::wallet::Args;
use nox_shield_core::ffi::{CancelToken, Wallet};

pub fn call(w: &Wallet, method: &str, a: &Args) -> Answer {
    Some(match method {
        // The page stops a proof by ending the worker, so the token is never cancelled from here.
        "sendPrivate" => {
            (|| w.send_private(a.coin(0)?, a.text(1)?, a.text(2)?, a.flag(3)?, CancelToken::new()))(
            )
            .map(|t| spend_ticket(&t))
        }
        "withdraw" => {
            (|| w.withdraw(a.coin(0)?, a.text(1)?, a.text(2)?, a.flag(3)?, CancelToken::new()))()
                .map(|t| spend_ticket(&t))
        }
        "quoteSpend" => (|| w.quote_spend(a.coin(0)?, a.text(1)?, a.flag(2)?))().map(|q| {
            Json::obj()
                .str("networkFee", &q.network_fee)
                .str("protocolFee", &q.protocol_fee)
                .str("totalFee", &q.total_fee)
                .num("rung", q.rung)
                .str("baseFeeGwei", &q.base_fee_gwei)
                .opt("refusal", q.refusal.as_deref())
                .done()
        }),
        "freshWithdrawalAddress" => {
            w.fresh_withdrawal_address().map(|addr| addr.map_or("null".into(), |s| text(&s)))
        }
        "addressUsed" => a.text(0).and_then(|addr| w.address_used(addr)).map(|u| u.to_string()),
        _ => return None,
    })
}
