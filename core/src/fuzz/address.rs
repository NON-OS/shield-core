//! A receiving address a user pasted: any text, parsed or refused.

use crate::keys::parse_receiving_address;

pub fn address(bytes: &[u8]) {
    if let Ok(text) = core::str::from_utf8(bytes) {
        let _ = parse_receiving_address(text);
    }
}
