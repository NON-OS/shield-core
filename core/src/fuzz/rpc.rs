//! A reply from an RPC, which is a server that owes this wallet nothing: any
//! text, read as each of the replies the wallet decodes, or refused.

use crate::net::rpc::{call_results, parse_block_number, parse_logs};

pub fn rpc(bytes: &[u8]) {
    if let Ok(text) = core::str::from_utf8(bytes) {
        let _ = parse_block_number(text);
        let _ = parse_logs(text);
        let _ = call_results(text, 12);
    }
}
