use wasm_bindgen::prelude::wasm_bindgen;

/// The periodic tree root this prover was built for, as hex. The page compares it with the
/// release manifest before it loads a cache, so a cache for another circuit is never fetched.
#[wasm_bindgen]
pub fn periodic_root() -> String {
    nox_prover::PERIODIC_ROOT.iter().map(|b| format!("{b:02x}")).collect()
}
