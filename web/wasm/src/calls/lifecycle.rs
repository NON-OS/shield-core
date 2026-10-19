//! Making, restoring, opening and closing the wallet.

use super::Answer;
use crate::json::{list, text};
use crate::views::balance;
use crate::wallet::Args;
use nox_shield_core::ffi::Wallet;

pub fn call(w: &Wallet, method: &str, a: &Args) -> Answer {
    Some(match method {
        "stored" => Ok(w.stored().to_string()),
        "unlocked" => w.unlocked().map(|u| u.to_string()),
        "create" => w.create().map(|words| list(words.iter().map(|x| text(x)))),
        "restore" => w.restore(a.rest(0)).map(|()| "null".into()),
        "restoreFromKey" => a.text(0).and_then(|k| w.restore_from_key(k)).map(|()| "null".into()),
        "fromKey" => w.from_key().map(|f| f.to_string()),
        "unlock" => w.unlock().map(|()| "null".into()),
        "lock" => w.lock().map(|()| "null".into()),
        "recoveryWords" => w
            .recovery_words()
            .map(|words| words.map_or("null".into(), |ws| list(ws.iter().map(|x| text(x))))),
        "wipe" => w.wipe().map(|done| done.to_string()),
        "receivingAddress" => w.receiving_address().map(|s| text(&s)),
        "balances" => w.balances().map(|bs| list(bs.iter().map(balance))),
        "depositNotes" => w.deposit_notes().map(|bs| list(bs.iter().map(balance))),
        "exportPublicKey" => a.index(0).and_then(|i| w.export_public_key(i)).map(|s| text(&s)),
        _ => return None,
    })
}
