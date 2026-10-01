//! Where a request goes and how it leaves. No address ships in the binary, so traffic does not
//! converge on one sequencer.

/// How a connection leaves the device: Tor or Nym on loopback. There is no direct route, since
/// a wallet that can point at clearnet will, by a support article or a slipped default.
#[derive(Clone, Copy, PartialEq, Eq, Debug, uniffi::Enum)]
pub enum Route {
    Tor,
    Nym,
}

/// The sequencer's address, and the local proxy that reaches it.
#[derive(Clone, PartialEq, Eq, Debug, uniffi::Record)]
pub struct Endpoint {
    /// An onion name for Tor, or the address the Nym client maps to the service.
    pub host: String,
    pub port: u16,
    pub proxy_host: String,
    pub proxy_port: u16,
    pub route: Route,
}

impl Endpoint {
    pub fn proxy_default(route: Route) -> u16 {
        default_proxy_port(route)
    }
}

/// The port a route's client listens on: Orbot's SOCKS5 on 9050, Nym's on 1080.
#[uniffi::export]
pub fn default_proxy_port(route: Route) -> u16 {
    match route {
        Route::Tor => 9050,
        Route::Nym => 1080,
    }
}
