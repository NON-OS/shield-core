//! The worker's side of the in-memory files: what to load before the wallet opens, and what to
//! store after each call.

use crate::json::{list, text, Json};
use nox_shield_core::fs::memory::{load, take_changes};
use std::path::PathBuf;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub fn load_file(path: String, bytes: Vec<u8>) {
    load(PathBuf::from(path), bytes);
}

/// The files changed since the last call, as `[{path, bytes}]` with bytes as hex, or null where the
/// file was removed. Hex keeps the boundary to one string; the files are small but for the notes.
#[wasm_bindgen]
pub fn changed_files() -> String {
    list(take_changes().into_iter().map(|(path, bytes)| {
        let path = path.to_string_lossy().into_owned();
        let bytes = bytes.map(|b| b.iter().map(|x| format!("{x:02x}")).collect::<String>());
        Json::obj()
            .str("path", &path)
            .raw("bytes", &bytes.map_or("null".into(), |h| text(&h)))
            .done()
    }))
}
