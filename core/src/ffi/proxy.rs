//! Whether the local proxy is running, asked from a screen.
//!
//! A first run that only says the sequencer is unreachable leaves a person
//! guessing which half is wrong. The answer is a yes or a no, and the reason a
//! proxy refused is a detail for a log this app does not keep.

use crate::net::socks5::probe;
use crate::net::Route;

/// Whether the route's local proxy is running and speaks the shape this wallet
/// needs. Loopback only, and nothing leaves the device.
#[uniffi::export]
pub fn proxy_answers(route: Route) -> bool {
    probe(route).is_ok()
}
