use nox_shield_core::fs::read;
use wasm_bindgen::prelude::wasm_bindgen;

/// A file the wallet wrote, for the page to offer as a download: the proof hand-off files that
/// the apps share with the system sheet. None when there is no such file.
#[wasm_bindgen]
pub fn read_file(path: String) -> Option<Vec<u8>> {
    read(path).ok()
}
