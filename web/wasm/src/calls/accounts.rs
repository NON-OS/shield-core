//! The accounts one phrase holds.

use super::Answer;
use crate::json::{list, text};
use crate::views::{account_summary, watched_summary};
use crate::wallet::Args;
use nox_shield_core::ffi::Wallet;

pub fn call(w: &Wallet, method: &str, a: &Args) -> Answer {
    Some(match method {
        "accounts" => w.accounts().map(|all| list(all.iter().map(account_summary))),
        "addAccount" => w.add_account().map(|i| i.to_string()),
        "selectAccount" => a.index(0).and_then(|i| w.select_account(i)).map(|()| "null".into()),
        "findAccounts" => w.find_accounts().map(|n| n.to_string()),
        "accountSearchProgress" => Ok(w.account_search_progress().to_string()),
        "ownAccountOf" => a
            .text(0)
            .and_then(|addr| w.own_account_of(addr))
            .map(|i| i.map_or("null".into(), |i| i.to_string())),
        "arrivedRecently" => w.arrived_recently().map(|r| r.to_string()),
        "publicAddress" => w.public_address().map(|s| text(&s)),
        "importViewKey" => a.text(0).and_then(|key| w.import_view_key(key)).map(|i| i.to_string()),
        "watchedAccounts" => w.watched_accounts().map(|all| list(all.iter().map(watched_summary))),
        "forgetViewKey" => a.index(0).and_then(|i| w.forget_view_key(i)).map(|()| "null".into()),
        _ => return None,
    })
}
