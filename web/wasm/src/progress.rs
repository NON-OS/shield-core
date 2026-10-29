//! A proof's phases, handed to the page as they finish. The worker defines `shieldPhase`, which
//! posts each one to the page while the proof keeps its thread. The prover reports from the thread
//! that called it, never from the pool, and a thread without the function drops the report.

use nox_prover::Phase;
use nox_shield_core::prover::Progress;
use std::sync::Arc;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(catch, js_namespace = globalThis, js_name = shieldPhase)]
    fn shield_phase(phase: &str, done: f32) -> Result<(), JsValue>;
}

#[cfg(not(target_arch = "wasm32"))]
fn shield_phase(_phase: &str, _done: f32) -> Result<(), JsValue> {
    Ok(())
}

/// The name the page knows a phase by.
pub fn name(p: Phase) -> &'static str {
    match p {
        Phase::Request => "request",
        Phase::Blinding => "blinding",
        Phase::Region => "region",
        Phase::Products => "products",
        Phase::Periodic => "periodic",
        Phase::Composition => "composition",
        Phase::CompositionTree => "composition-tree",
        Phase::Deep => "deep",
        Phase::Fri => "fri",
        Phase::Queries => "queries",
        Phase::Verified => "verified",
    }
}

/// Report one finished phase to the page.
pub fn report(p: Phase, done: f32) {
    let _ = shield_phase(name(p), done);
}

/// The observer a spend's token carries.
pub fn to_page() -> Progress {
    Arc::new(report)
}

/// One proof of `request` from the periodic cache, reporting its phases, as the prover's JSON.
/// The Measure screen times the pinned test vector with it.
#[wasm_bindgen]
pub fn prove_reporting(
    request: &str,
    seed: &str,
    entropy: &[u8],
    cache: &[u8],
) -> Result<String, JsValue> {
    let opts = nox_prover::Options { cache: Some(cache), progress: Some(&report), cancel: None };
    nox_prover::prove_with(request, seed, entropy, &opts)
        .map(|(p, _)| nox_prover::to_json(&p))
        .map_err(|e| JsValue::from_str(&e.to_string()))
}
