//! The network side. Every byte leaves the device through a SOCKS5 proxy that
//! the user's platform provides, Orbot or a Nym client, and the policy module
//! refuses an endpoint that would carry the connection in the clear. An RPC
//! from a phone otherwise tells the endpoint which notes belong to which
//! address, which is the leak the proof cannot cover.

pub mod asset;
pub mod asset_v2;
pub(crate) mod endpoint;
pub mod explorer;
pub mod fee_quote;
pub mod fee_schedule;
#[cfg(feature = "fuzzing")]
pub mod fuzz_hook;
pub(crate) mod onion;
mod policy;
pub mod pool;
pub mod pool_errors;
mod pools;
pub mod relay;
pub mod rpc;
pub(crate) mod socks5;
pub mod tor;

pub use endpoint::{default_proxy_port, Endpoint, Route};

/// Check an endpoint against the privacy policy. Exposed so a wallet can refuse
/// a configuration when it is set, not only when a connection is opened.
pub fn check_endpoint(endpoint: &Endpoint) -> Result<(), crate::error::NetError> {
    policy::check(endpoint)
}
