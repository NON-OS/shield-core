//! The public account: balances, sends and their status.

use super::Answer;
use crate::json::text;
use crate::views::{public_balances, public_review, public_sent, public_swap};
use crate::wallet::Args;
use nox_shield_core::error::WalletError;
use nox_shield_core::evm::SendStatus;
use nox_shield_core::ffi::Wallet;

pub fn call(w: &Wallet, method: &str, a: &Args) -> Answer {
    Some(match method {
        "publicBalances" => {
            a.network(0).and_then(|n| w.public_balances(n)).map(|b| public_balances(&b))
        }
        "publicMax" => (|| w.public_max(a.network(0)?, a.coin(1)?))().map(|s| text(&s)),
        "reviewPublicSend" => {
            (|| w.review_public_send(a.network(0)?, a.coin(1)?, a.text(2)?, a.text(3)?))()
                .map(|r| public_review(&r))
        }
        "reviewPublicSwap" => (|| {
            let bps = u16::try_from(a.number(4)?).map_err(|_| WalletError::Amount)?;
            w.review_public_swap(a.network(0)?, a.coin(1)?, a.coin(2)?, a.text(3)?, bps)
        })()
        .map(|s| public_swap(&s)),
        "networkHasSwaps" => a.network(0).map(|n| n.chain().swaps.is_some().to_string()),
        "confirmPublicSend" => {
            a.number(0).and_then(|id| w.confirm_public_send(id)).map(|s| public_sent(&s))
        }
        "publicSendStatus" => (|| w.public_send_status(a.network(0)?, a.text(1)?))().map(|s| {
            text(match s {
                SendStatus::Pending => "pending",
                SendStatus::Confirmed => "confirmed",
                SendStatus::Failed => "failed",
            })
        }),
        _ => return None,
    })
}
