//! The SOCKS5 greeting.

use crate::error::NetError;
use std::io::{Read, Write};
use std::net::TcpStream;

const VERSION: u8 = 5;
const NO_AUTH: u8 = 0;

/// Offer no authentication only. A proxy asking for credentials is not the expected local
/// client, so the connection is dropped, never negotiated.
pub fn greet(stream: &mut TcpStream) -> Result<(), NetError> {
    stream.write_all(&[VERSION, 1, NO_AUTH]).map_err(|_| NetError::Transport)?;
    let mut answer = [0u8; 2];
    stream.read_exact(&mut answer).map_err(|_| NetError::Transport)?;
    match answer {
        [VERSION, NO_AUTH] => Ok(()),
        [VERSION, _] => Err(NetError::ProxyRefused),
        _ => Err(NetError::ProxyProtocol),
    }
}
