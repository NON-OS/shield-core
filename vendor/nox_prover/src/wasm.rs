// NONOS Operating System (AGPL-3.0-or-later)
//! The browser interface.
//!
//! ```text
//! import init, { prove } from "./nox_prover.js";
//! await init();
//! const entropy = crypto.getRandomValues(new Uint8Array(512));
//! const json = prove(requestText, seedText, entropy);
//! ```
//!
//! With the periodic cache, `prove_with_cache(requestText, seedText, entropy,
//! cache)` skips a quarter of the work. The cache is the same for every spend,
//! so an app ships it: `NOX_CACHE=<file> nox_bench ...` writes it once. It is
//! checked, not trusted: a wrong one is an error, never a bad proof.
//!
//! Built with `wasm-threads`, call it from a Web Worker, never the page's main
//! thread, and start the pool first. That needs the page served with `Cross-Origin-Opener-Policy: same-origin` and
//! `Cross-Origin-Embedder-Policy: require-corp`:
//!
//! ```text
//! import init, { initThreadPool, prove } from "./nox_prover.js";
//! await init();
//! await initThreadPool(navigator.hardwareConcurrency);
//! ```
//!
//! `prove` returns the proof as JSON (`to_json`) or throws the reason. The
//! JSON holds the spender's new secrets.

use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;
// The export `initThreadPool` comes from the crate's own wasm-bindgen
// attribute; the name is here for the reader.
#[cfg(feature = "wasm-threads")]
#[allow(unused_imports)]
pub use wasm_bindgen_rayon::init_thread_pool;

#[wasm_bindgen]
pub fn prove(request: &str, seed: &str, entropy: &[u8]) -> Result<String, JsValue> {
    crate::prove(request, seed, entropy)
        .map(|p| crate::to_json(&p))
        .map_err(|why| JsValue::from_str(&why))
}

#[wasm_bindgen]
pub fn prove_with_cache(request: &str, seed: &str, entropy: &[u8], cache: &[u8]) -> Result<String, JsValue> {
    crate::prove_with_cache(request, seed, entropy, cache)
        .map(|p| crate::to_json(&p))
        .map_err(|why| JsValue::from_str(&why))
}
