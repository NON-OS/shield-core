//! Replies from servers that owe this wallet nothing: account RPCs, the lander and contracts.

/// Any text, read as every answer the account reads, a block, a nonce line and a swap market.
pub fn account(bytes: &[u8]) {
    if let Ok(text) = core::str::from_utf8(bytes) {
        crate::evm::fuzz_hook::reply(text);
    }
}

/// A status from the first two bytes and any body, read as a hand-off, a state and an info page.
pub fn lander(bytes: &[u8]) {
    let status = u16::from_be_bytes([
        bytes.first().copied().unwrap_or(0),
        bytes.get(1).copied().unwrap_or(0),
    ]);
    if let Ok(body) = core::str::from_utf8(bytes.get(2..).unwrap_or_default()) {
        crate::net::fuzz_hook::lander(status, body);
    }
}

pub fn policy(bytes: &[u8]) {
    crate::net::fuzz_hook::policy(bytes);
    crate::wallet::fuzz_hook::registry(bytes);
}
