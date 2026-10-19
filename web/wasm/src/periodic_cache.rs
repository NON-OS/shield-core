use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

/// The periodic cache, built by proving one spend from scratch. The tree is the same whichever
/// spend builds it, so the release build makes it from the pinned test vector and ships it.
#[wasm_bindgen]
pub fn periodic_cache(request: &str, seed: &str, entropy: &[u8]) -> Result<Vec<u8>, JsValue> {
    nox_prover::prove_keeping_cache(request, seed, entropy)
        .map(|(_, cache)| cache)
        .map_err(|why| JsValue::from_str(&why.to_string()))
}
