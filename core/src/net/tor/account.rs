//! Circuits per account, so an exit cannot link two accounts of a wallet. The pool scan is the
//! same for every wallet and stays shared.

use arti_client::IsolationToken;
use std::cell::Cell;
use std::sync::Mutex;

thread_local! {
    /// An account this thread works for, over the active one, so a search runs accounts at once.
    static THIS_THREAD: Cell<Option<u32>> = const { Cell::new(None) };
}

/// One isolation token per account, made the first time the account connects.
#[derive(Default)]
pub(super) struct Accounts {
    tokens: Mutex<Vec<IsolationToken>>,
    active: std::sync::atomic::AtomicU32,
}

impl Accounts {
    /// The token of the active account. A poisoned lock gets a fresh token, which shares nothing.
    pub(super) fn token(&self) -> IsolationToken {
        let active = self.active.load(std::sync::atomic::Ordering::Acquire);
        let index = THIS_THREAD.with(Cell::get).unwrap_or(active);
        let Ok(mut tokens) = self.tokens.lock() else { return IsolationToken::new() };
        let index = usize::try_from(index).unwrap_or(usize::MAX);
        while tokens.len() <= index && tokens.len() < 64 {
            tokens.push(IsolationToken::new());
        }
        tokens.get(index).copied().unwrap_or_else(IsolationToken::new)
    }
}

/// Run `work` on this thread with every connection on the circuits of account `index`.
pub fn as_account<T>(index: u32, work: impl FnOnce() -> T) -> T {
    THIS_THREAD.with(|c| c.set(Some(index)));
    let out = work();
    THIS_THREAD.with(|c| c.set(None));
    out
}

impl super::Tor {
    pub fn use_account(&self, index: u32) {
        self.accounts.active.store(index, std::sync::atomic::Ordering::Release);
    }
}
