//! TLS over a Tor stream, for an RPC that is not an onion service.
//!
//! A Tor exit sees the bytes it carries to a clearnet endpoint, so a request to
//! an HTTPS RPC is wrapped in TLS end to end: the exit sees ciphertext, and the
//! endpoint's certificate is checked against the bundled web PKI roots rather
//! than anything the platform or the exit could substitute.

use super::TorStream;
use crate::error::NetError;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::sync::Arc;

/// Wrap `stream` in TLS to `host`, verifying its certificate chain.
pub fn tls(
    stream: TorStream,
    host: &str,
) -> Result<StreamOwned<ClientConnection, TorStream>, NetError> {
    let roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|_| NetError::Transport)?
            .with_root_certificates(roots)
            .with_no_client_auth();
    let name = ServerName::try_from(host.to_owned()).map_err(|_| NetError::EndpointRefused)?;
    let conn = ClientConnection::new(Arc::new(config), name).map_err(|_| NetError::Transport)?;
    Ok(StreamOwned::new(conn, stream))
}
