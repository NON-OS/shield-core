//! The SOCKS5 connect reply.

use crate::error::NetError;
use std::io::Read;
use std::net::TcpStream;

/// Read the connect reply and discard the bound address. An address type outside RFC 1928 is
/// a protocol error, since guessing its length would desync every later byte.
pub fn read(stream: &mut TcpStream) -> Result<(), NetError> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).map_err(|_| NetError::Transport)?;
    if head[0] != 5 {
        return Err(NetError::ProxyProtocol);
    }
    if head[1] != 0 {
        return Err(NetError::ProxyRefused);
    }
    let addr_len = match head[3] {
        1 => 4,
        3 => {
            let mut n = [0u8; 1];
            stream.read_exact(&mut n).map_err(|_| NetError::Transport)?;
            usize::from(n[0])
        }
        4 => 16,
        _ => return Err(NetError::ProxyProtocol),
    };
    let mut rest = vec![0u8; addr_len.saturating_add(2)];
    stream.read_exact(&mut rest).map_err(|_| NetError::Transport)?;
    Ok(())
}
