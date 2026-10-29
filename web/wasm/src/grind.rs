//! The grind on the GPU, where the worker found one worth using. The prover calls the grinder
//! from the thread that holds the proof; the worker's `shieldGrind` blocks there until the GPU
//! answers. A thread without it, a GPU that fails or a nonce that misses the work all leave the
//! search to the cores, so the GPU can cost time and never a proof.

use nonos_stark::grinder::{clear_grinder, meets, set_grinder};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(catch, js_namespace = globalThis, js_name = shieldGrind)]
    fn shield_grind(lanes: &[u32], bits: u32) -> Result<f64, JsValue>;
}

#[cfg(not(target_arch = "wasm32"))]
fn shield_grind(_lanes: &[u32], _bits: u32) -> Result<f64, JsValue> {
    Ok(-1.0)
}

fn halves(template: &[u64; 25]) -> [u32; 50] {
    let mut lanes = [0u32; 50];
    for (i, w) in template.iter().enumerate() {
        lanes[2 * i] = *w as u32;
        lanes[2 * i + 1] = (*w >> 32) as u32;
    }
    lanes
}

fn template(lanes: &[u32]) -> [u64; 25] {
    let mut t = [0u64; 25];
    for (i, w) in t.iter_mut().enumerate() {
        let lo = lanes.get(2 * i).copied().unwrap_or(0);
        let hi = lanes.get(2 * i + 1).copied().unwrap_or(0);
        *w = u64::from(lo) | (u64::from(hi) << 32);
    }
    t
}

fn on_gpu(t: &[u64; 25], bits: u32) -> Option<u64> {
    match shield_grind(&halves(t), bits) {
        Ok(n) if n >= 0.0 && n.fract() == 0.0 => Some(n as u64),
        _ => None,
    }
}

/// Grind on the GPU from now on, or on the cores again.
#[wasm_bindgen]
pub fn use_gpu_grinder(on: bool) {
    if on {
        set_grinder(on_gpu);
    } else {
        clear_grinder();
    }
}

/// The smallest nonce meeting `bits` against a template, searched here one at a time, which a
/// GPU must match before it is used.
#[wasm_bindgen]
pub fn grind_reference(lanes: &[u32], bits: u32) -> f64 {
    let t = template(lanes);
    (0u64..).find(|&n| meets(&t, n, bits)).map_or(-1.0, |n| n as f64)
}
