//! Into the pool and, for a spend no lander takes, onto it from the user's own account.

use super::Answer;
use crate::views::{deposit_ticket, public_shield};
use crate::wallet::Args;
use nox_shield_core::ffi::Wallet;

pub fn call(w: &Wallet, method: &str, a: &Args) -> Answer {
    Some(match method {
        "reviewShield" => (|| w.review_shield(a.coin(0)?, a.text(1)?))().map(|s| public_shield(&s)),
        "prepareDeposit" => {
            (|| w.prepare_deposit(a.coin(0)?, a.text(1)?, a.text(2)?))().map(|t| deposit_ticket(&t))
        }
        "reviewSelfSettle" => w.review_self_settle().map(|s| public_shield(&s)),
        _ => return None,
    })
}
