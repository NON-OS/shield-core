//! Opening a connection through the local proxy. The host goes by name, since resolving it
//! here would leak it to DNS, and an onion name has nothing to resolve.

use super::greet::greet;
use super::reply;
use crate::error::NetError;
use crate::net::endpoint::Endpoint;
use crate::net::policy::check;
use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

/// End to end limit: long enough for honest mixnet and onion traffic, short of a hung screen.
const TIMEOUT: Duration = Duration::from_secs(90);

const HOST_MAX: usize = 255;

/// The single place the wallet opens a socket, only to the local proxy and only by address,
/// since a name would be resolved.
pub(super) fn dial(address: SocketAddr, timeout: Duration) -> Result<TcpStream, NetError> {
    TcpStream::connect_timeout(&address, timeout).map_err(|_| NetError::ProxyUnreachable)
}

/// Open a connection through the endpoint's proxy. The policy check runs before any socket.
pub fn open(endpoint: &Endpoint) -> Result<TcpStream, NetError> {
    check(endpoint)?;
    let host = endpoint.host.as_bytes();
    if host.is_empty() || host.len() > HOST_MAX {
        return Err(NetError::EndpointRefused);
    }
    let ip: IpAddr = endpoint.proxy_host.parse().map_err(|_| NetError::EndpointRefused)?;
    let mut stream = dial(SocketAddr::new(ip, endpoint.proxy_port), TIMEOUT)?;
    stream.set_read_timeout(Some(TIMEOUT)).map_err(|_| NetError::Transport)?;
    stream.set_write_timeout(Some(TIMEOUT)).map_err(|_| NetError::Transport)?;
    stream.set_nodelay(true).map_err(|_| NetError::Transport)?;
    greet(&mut stream)?;

    let mut request = Vec::with_capacity(host.len().saturating_add(7));
    request.extend_from_slice(&[5, 1, 0, 3]);
    let len = u8::try_from(host.len()).map_err(|_| NetError::EndpointRefused)?;
    request.push(len);
    request.extend_from_slice(host);
    request.extend_from_slice(&endpoint.port.to_be_bytes());
    stream.write_all(&request).map_err(|_| NetError::Transport)?;
    reply::read(&mut stream)?;
    Ok(stream)
}
