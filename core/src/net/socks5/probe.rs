//! Whether the local proxy is running, so a screen can tell "start Tor" from "the service is
//! down". It completes a SOCKS5 greeting on loopback and closes: no host is named, no circuit
//! built, nothing leaves the device.

use super::greet::greet;
use crate::error::NetError;
use crate::net::endpoint::{default_proxy_port, Route};
use std::net::SocketAddr;
use std::time::Duration;

/// Never a caller's host, or the probe would let anyone make this device connect somewhere.
const LOOPBACK: &str = "127.0.0.1";

/// A local client answers its own greeting immediately or it is not running.
const TIMEOUT: Duration = Duration::from_secs(2);

/// Whether the route's local proxy answers SOCKS5 with no authentication.
pub fn probe(route: Route) -> Result<(), NetError> {
    let port = default_proxy_port(route);
    let address = SocketAddr::new(LOOPBACK.parse().map_err(|_| NetError::Transport)?, port);
    probe_at(address)
}

/// The same probe at a given address, for tests on an ephemeral port. Never exposed.
pub(super) fn probe_at(address: SocketAddr) -> Result<(), NetError> {
    let mut stream = super::connect::dial(address, TIMEOUT)?;
    stream.set_read_timeout(Some(TIMEOUT)).map_err(|_| NetError::Transport)?;
    stream.set_write_timeout(Some(TIMEOUT)).map_err(|_| NetError::Transport)?;
    greet(&mut stream)
}
