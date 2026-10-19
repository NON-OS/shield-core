//! The transport of a build without Tor, which is the browser build. A page cannot open a socket,
//! so there is nothing to carry a stream: `Tor` has no value, and every path that would connect
//! through one is unreachable, which the compiler checks. The web shell makes its own requests to
//! endpoints the user chose and hands the replies to the same parsers the native shells use.

mod account;
mod stream;
mod tls;

pub use account::as_account;
pub use stream::TorStream;
pub use tls::tls;

use crate::error::NetError;
use std::path::Path;

/// The same purposes as the Tor build's, so every caller compiles unchanged. A purpose added there
/// and used anywhere fails this build until it is added here too.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    Scan,
    Relay,
    Deposit,
    Mainnet,
    Sepolia,
}

pub enum Tor {}

impl Tor {
    /// Always refused, with the sentence the shells already show for a missing proxy.
    pub fn start(_dir: &Path) -> Result<Tor, NetError> {
        Err(NetError::ProxyUnreachable)
    }

    pub fn connect(&self, _: Purpose, _: &str, _: u16) -> Result<TorStream, NetError> {
        match *self {}
    }

    pub fn connect_within(
        &self,
        _: Purpose,
        _: (&str, u16),
        _: std::time::Duration,
    ) -> Result<TorStream, NetError> {
        match *self {}
    }

    pub fn use_account(&self, _: u32) {
        match *self {}
    }
}
