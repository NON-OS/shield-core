//! The account search after a restore, run off the worker's own thread so the worker can still
//! answer how far it has looked. The one-thread build has no other thread, so there the search
//! runs in place and the count is read when it ends.

use super::failure::failure;
use super::WebWallet;
use std::sync::{Arc, Mutex};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

#[wasm_bindgen]
impl WebWallet {
    pub fn search_start(&self) {
        let wallet = self.wallet.clone();
        let done = Arc::clone(&self.search);
        let work = move || {
            let found = wallet.find_accounts();
            if let Ok(mut slot) = done.lock() {
                *slot = Some(found);
            }
        };
        if let Ok(mut slot) = self.search.lock() {
            *slot = None;
        }
        #[cfg(feature = "threads")]
        rayon::spawn(work);
        #[cfg(not(feature = "threads"))]
        work();
    }

    pub fn search_progress(&self) -> u32 {
        self.wallet.account_search_progress()
    }

    /// The accounts the wallet has once the search ended, null while it runs.
    pub fn search_result(&self) -> Result<Option<u32>, JsValue> {
        let slot = self.search.lock().map_err(|_| JsValue::from_str("the search lock failed"))?;
        match slot.as_ref() {
            None => Ok(None),
            Some(Ok(n)) => Ok(Some(*n)),
            Some(Err(e)) => Err(failure(*e)),
        }
    }
}

pub(super) type Search = Arc<Mutex<Option<Result<u32, nox_shield_core::error::WalletError>>>>;
