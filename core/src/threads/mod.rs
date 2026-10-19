//! Scoped threads. Natively they are std's. A browser page cannot start a thread from Rust, so
//! there each spawned closure runs to the end where it is spawned, which keeps the result and
//! loses only the overlap.

#[cfg(target_arch = "wasm32")]
mod inline;

#[cfg(target_arch = "wasm32")]
pub use inline::scope;
#[cfg(not(target_arch = "wasm32"))]
pub use std::thread::scope;
