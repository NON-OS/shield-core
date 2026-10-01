//! The check that decides whether a request may leave at all. There is no override and no
//! development exception.

use super::endpoint::{Endpoint, Route};
use super::onion::is_onion;
use crate::error::NetError;

/// Refuse an endpoint the proof cannot protect. The proxy must be loopback. Tor must name a
/// decoded v3 onion, since any other host lets an exit link an address to an IP. Nym must not
/// name a raw IP.
pub fn check(endpoint: &Endpoint) -> Result<(), NetError> {
    if !loopback(&endpoint.proxy_host) || endpoint.proxy_port == 0 || endpoint.port == 0 {
        return Err(NetError::EndpointRefused);
    }
    let host = endpoint.host.trim().to_lowercase();
    let acceptable = match endpoint.route {
        Route::Tor => is_onion(&host),
        Route::Nym => !host.is_empty() && !looks_numeric(&host),
    };
    if acceptable {
        Ok(())
    } else {
        Err(NetError::EndpointRefused)
    }
}

fn loopback(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "::1" | "localhost")
}
/// A host that parses as an address. Judged textually, since a DNS lookup would be the leak.
/// resolver is consulted: a DNS lookup here would itself be the leak.
fn looks_numeric(host: &str) -> bool {
    host.contains(':') || host.chars().all(|c| c.is_ascii_digit() || c == '.')
}
