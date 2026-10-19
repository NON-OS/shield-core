use crate::json::Json;
use nox_shield_core::ffi::PublicSent;

pub fn public_sent(s: &PublicSent) -> String {
    Json::obj().str("hash", &s.hash).str("link", &s.link).done()
}
