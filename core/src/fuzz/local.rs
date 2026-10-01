//! Bytes from the person and the device: what is typed or pasted, and the files a phone keeps.

use crate::custody::{parse_key, Phrase};
use crate::keys::view_key_read::parse_view_key;
use crate::wallet::rewards::{parse_signature, signer};

/// A view key, a private key, recovery words, an address, an amount and a signature.
pub fn typed(bytes: &[u8]) {
    let Ok(text) = core::str::from_utf8(bytes) else { return };
    let _ = parse_view_key(text);
    let _ = parse_key(text);
    let words: Vec<String> = text.split_whitespace().map(str::to_string).collect();
    let _ = Phrase::parse(&words);
    crate::ffi::fuzz_hook::typed(text);
    if let Some(signature) = parse_signature(text) {
        let _ = signer(&[7u8; 32], &signature);
    }
}

/// The vault container, the files of a hand-off and the record of its publication.
pub fn disk(bytes: &[u8]) {
    let _ = crate::custody::format::decode(bytes);
    crate::wallet::fuzz_hook::disk(bytes);
}
