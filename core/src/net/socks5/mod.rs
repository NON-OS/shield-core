//! A SOCKS5 client, the no authentication and connect by name subset of RFC
//! 1928. By name matters: resolving the host locally would leak it to a DNS
//! server, and for an onion name there is nothing to resolve.

mod connect;
mod greet;
mod probe;
#[cfg(test)]
#[path = "probe_test.rs"]
mod probe_test;
mod reply;

pub use connect::open;
pub use probe::probe;
