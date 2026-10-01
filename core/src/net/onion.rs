//! Whether a host is a real version 3 onion name, not a string ending in `.onion`. Length,
//! alphabet, decoded size and version are checked, which catches invented names and all but
//! one in 256 typos. The SHA3 checksum is a named gap: this crate carries no SHA3.

use crate::keys::base32_read;

/// The label length of a version 3 onion name.
const LABEL: usize = 56;

/// 32 bytes of public key, 2 of checksum, 1 of version.
const DECODED: usize = 35;

/// The only version this speaks to.
const VERSION: u8 = 3;

/// True when the host is a version 3 onion name.
pub fn is_onion(host: &str) -> bool {
    let Some(label) = host.strip_suffix(".onion") else {
        return false;
    };
    if label.len() != LABEL {
        return false;
    }
    let Some(raw) = base32_read::decode(label) else {
        return false;
    };
    raw.len() == DECODED && raw.last() == Some(&VERSION)
}
