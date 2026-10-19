//! The transport of the browser build. A page cannot open a socket or run Tor, so each request
//! the core writes is sent by the browser itself, from the user's own address, to the endpoint the
//! core named. The page says so before the first one. Onion services cannot be reached from a
//! normal browser, and a connection to one is refused here rather than tried.

mod account;
mod exchange;
mod stream;
mod tls;
mod xhr;

pub use account::as_account;
pub use stream::TorStream;
pub use tls::tls;

use crate::error::NetError;
use std::path::Path;

/// The same purposes as the Tor build's, so every caller compiles unchanged. A browser has one
/// path for all of them, which is the difference the page tells the user about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    Scan,
    Relay,
    Deposit,
    Mainnet,
    Sepolia,
}

pub struct Tor;

impl Tor {
    pub fn start(_dir: &Path) -> Result<Tor, NetError> {
        Ok(Tor)
    }

    /// A stream to `host` over HTTPS. Anything but port 443 on a public name is refused, which
    /// leaves out the onion landers and every plain connection.
    pub fn connect(&self, _: Purpose, host: &str, port: u16) -> Result<TorStream, NetError> {
        if port != 443 || host.ends_with(".onion") {
            return Err(NetError::ProxyRefused);
        }
        Ok(TorStream::to(host))
    }

    pub fn connect_within(
        &self,
        purpose: Purpose,
        (host, port): (&str, u16),
        _: std::time::Duration,
    ) -> Result<TorStream, NetError> {
        self.connect(purpose, host, port)
    }

    pub fn use_account(&self, _: u32) {}
}
