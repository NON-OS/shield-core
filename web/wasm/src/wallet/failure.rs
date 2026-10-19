//! A failure as the page reads it: which layer, which case, and the core's own sentence. None of
//! it is built from a secret.

use crate::json::Json;
use nox_shield_core::error::WalletError;
use wasm_bindgen::JsValue;

pub fn failure(e: WalletError) -> JsValue {
    let detail = match e {
        WalletError::Custody { source } => format!("{source:?}"),
        WalletError::Store { source } => format!("{source:?}"),
        WalletError::Net { source } => format!("{source:?}"),
        WalletError::Prove { source } => format!("{source:?}"),
        _ => String::new(),
    };
    let kind = format!("{e:?}");
    let kind = kind.split([' ', '{']).next().unwrap_or_default();
    JsValue::from_str(
        &Json::obj().str("kind", kind).str("detail", &detail).str("text", &e.to_string()).done(),
    )
}
