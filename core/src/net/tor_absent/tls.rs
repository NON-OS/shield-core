//! The same call as the Tor build's, over a stream that cannot exist.

use super::TorStream;
use crate::error::NetError;

pub fn tls(stream: TorStream, _host: &str) -> Result<TorStream, NetError> {
    match stream {}
}
