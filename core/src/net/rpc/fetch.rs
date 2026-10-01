//! Reading the chain over a proxy, one connection per call. The endpoint sees a scan of the
//! pool and never an address of the wallet. Paging is the caller's loop.

use super::http::post;
use super::request;
use super::response::{self, RawLog};
use crate::error::NetError;
use crate::net::endpoint::Endpoint;
use crate::net::socks5::open;
use crate::net::tor::{tls, Purpose, Tor};

/// The chain head, to page a scan up to.
pub fn head(endpoint: &Endpoint) -> Result<u64, NetError> {
    let stream = open(endpoint)?;
    let reply = post(stream, &endpoint.host, "/", &request::block_number())?;
    response::block_number(text(&reply)?)
}

/// One page of an event's logs for an address. The query carries the address
/// and the topic and nothing else, so every wallet's request is identical.
pub fn page(
    endpoint: &Endpoint,
    address: &str,
    topic0: &str,
    from_block: u64,
    to_block: u64,
) -> Result<Vec<RawLog>, NetError> {
    let stream = open(endpoint)?;
    let body = request::get_logs(address, topic0, from_block, to_block);
    let reply = post(stream, &endpoint.host, "/", &body)?;
    response::logs(text(&reply)?)
}

fn text(bytes: &[u8]) -> Result<&str, NetError> {
    core::str::from_utf8(bytes).map_err(|_| NetError::ReplyShape)
}

/// One page of an event's logs from an HTTPS RPC, over the wallet's own Tor on
/// circuits reserved for scanning, TLS end to end so the exit sees ciphertext.
pub fn page_over_tor(
    tor: &Tor,
    host: &str,
    address: &str,
    topic0: &str,
    from_block: u64,
    to_block: u64,
) -> Result<Vec<RawLog>, NetError> {
    let stream = tls(tor.connect(Purpose::Scan, host, 443)?, host)?;
    let body = request::get_logs(address, topic0, from_block, to_block);
    let reply = post(stream, host, "/", &body)?;
    response::logs(text(&reply)?)
}

/// The chain head from an HTTPS RPC over the wallet's own Tor.
pub fn head_over_tor(tor: &Tor, host: &str) -> Result<u64, NetError> {
    let stream = tls(tor.connect(Purpose::Scan, host, 443)?, host)?;
    let reply = post(stream, host, "/", &request::block_number())?;
    response::block_number(text(&reply)?)
}

/// Every log of one event over a range, in windows of `window` blocks since free RPC tiers
/// cap a call. A refused window fails the whole scan, so no silent gap is left.
pub fn pages_over_tor(
    tor: &Tor,
    host: &str,
    address: &str,
    topic0: &str,
    from_block: u64,
    to_block: u64,
    window: u64,
) -> Result<Vec<RawLog>, NetError> {
    let step = window.checked_sub(1).ok_or(NetError::EndpointRefused)?;
    let mut out = Vec::new();
    let mut from = from_block;
    while from <= to_block {
        let to = from.saturating_add(step).min(to_block);
        out.extend(page_over_tor(tor, host, address, topic0, from, to)?);
        from = match to.checked_add(1) {
            Some(next) => next,
            None => break,
        };
    }
    Ok(out)
}

/// Read a view function of `to` over the wallet's own Tor, on the circuits of
/// `purpose`, TLS end to end.
pub fn call_over_tor(
    tor: &Tor,
    purpose: Purpose,
    host: &str,
    to: &str,
    data: &[u8],
) -> Result<Vec<u8>, NetError> {
    let stream = tls(tor.connect(purpose, host, 443)?, host)?;
    let reply = post(stream, host, "/", &request::eth_call(to, data))?;
    response::call_result(text(&reply)?)
}

/// Several view reads of `to` in one batched request over the wallet's own Tor.
pub fn calls_over_tor(
    tor: &Tor,
    purpose: Purpose,
    host: &str,
    to: &str,
    datas: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, NetError> {
    let stream = tls(tor.connect(purpose, host, 443)?, host)?;
    let reply = post(stream, host, "/", &request::eth_call_batch(to, datas))?;
    response::call_results(text(&reply)?, datas.len())
}

/// Batched view reads at one block over the wallet's own Tor.
pub fn calls_at_over_tor(
    tor: &Tor,
    purpose: Purpose,
    host: &str,
    to: &str,
    datas: &[Vec<u8>],
    block: u64,
) -> Result<Vec<Vec<u8>>, NetError> {
    let stream = tls(tor.connect(purpose, host, 443)?, host)?;
    let reply = post(stream, host, "/", &request::eth_call_batch_at(to, datas, block))?;
    response::call_results(text(&reply)?, datas.len())
}
