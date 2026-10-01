//! The hand-off files, the single-call cut and the registry replies a fuzzer reaches. Built only
//! with `fuzzing`.

use crate::evm::Viewed;

pub fn disk(bytes: &[u8]) {
    let _ = super::one_call(bytes);
    if let Ok(text) = core::str::from_utf8(bytes) {
        let _ = super::relay_body::limbs(text);
        let _ = super::publish::Published::from_text(text);
    }
}

pub fn registry(bytes: &[u8]) {
    let mut parts = bytes.chunks(64).map(|c| Viewed::Data(c.to_vec()));
    let found: Vec<Viewed> = parts.by_ref().take(4).collect();
    let _ = super::rewards::link_state(&found);
}
