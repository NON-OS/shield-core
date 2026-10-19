//! The clock. Natively it is std's. On wasm32 in a browser std has no clock and panics when asked,
//! so there it is the page's, through `web-time`, with the same types.

#[cfg(not(target_arch = "wasm32"))]
pub use std::time::{Instant, SystemTime, UNIX_EPOCH};
#[cfg(target_arch = "wasm32")]
pub use web_time::{Instant, SystemTime, UNIX_EPOCH};
