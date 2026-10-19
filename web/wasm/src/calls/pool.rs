//! Reading the pool, and following a spend until it settles.

use super::Answer;
use crate::json::Json;
use crate::views::chain_summary;
use crate::wallet::Args;
use nox_shield_core::ffi::Wallet;

pub fn call(w: &Wallet, method: &str, _: &Args) -> Answer {
    Some(match method {
        "syncChain" => w.sync_chain().map(|c| chain_summary(&c)),
        "takeBackPending" => w.take_back_pending().map(|n| n.to_string()),
        "followSpend" => w.follow_spend().map(|f| {
            Json::obj()
                .str("state", &f.state)
                .opt("tx", f.tx.as_deref())
                .opt("link", f.link.as_deref())
                .num("minutesSinceFirst", f.minutes_since_first)
                .num("timesPublished", f.times_published)
                .flag("selfSettleOffered", f.self_settle_offered)
                .opt("refusal", f.refusal.as_deref())
                .done()
        }),
        _ => return None,
    })
}
