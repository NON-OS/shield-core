//! The wallet as the page's worker holds it: the native core's `Wallet` with the passkey guard,
//! one call at a time by name, every answer JSON. The worker loads the stored files before the
//! first call and stores the changed ones after each.

mod args;
mod failure;
mod files;

pub use args::Args;

use crate::calls::dispatch;
use crate::guard::PasskeyGuard;
use failure::failure;
use nox_shield_core::ffi::Wallet;
use std::sync::Arc;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

#[wasm_bindgen]
pub struct WebWallet {
    wallet: Arc<Wallet>,
    guard: Arc<PasskeyGuard>,
}

#[wasm_bindgen]
impl WebWallet {
    /// The wallet kept under `dir` in the in-memory files.
    #[wasm_bindgen(constructor)]
    pub fn new(dir: String) -> Result<WebWallet, JsValue> {
        let guard = Arc::new(PasskeyGuard::default());
        let wallet = Wallet::new(dir, guard.clone()).map_err(failure)?;
        Ok(WebWallet { wallet, guard })
    }

    /// The passkey's PRF output, for the one create, restore or unlock that follows.
    pub fn hold_key(&self, secret: &[u8]) -> bool {
        self.guard.hold(secret)
    }

    /// Run `method` with `args`, as JSON, or throw the failure as `{kind, detail, text}`.
    pub fn call(&self, method: &str, args: Vec<String>) -> Result<String, JsValue> {
        match dispatch(&self.wallet, method, &Args::of(&args)) {
            Some(answer) => answer.map_err(failure),
            None => Err(JsValue::from_str(&format!("no call named {method}"))),
        }
    }
}

pub use files::{changed_files, load_file};
