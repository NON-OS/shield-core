//! The browser makes the TLS connection itself and checks the certificate, so there is nothing to
//! wrap here.

use super::TorStream;
use crate::error::NetError;

pub fn tls(stream: TorStream, _host: &str) -> Result<TorStream, NetError> {
    Ok(stream)
}
