//! A sealed note from an `OutputNote` log: any bytes, opened or refused under
//! one fixed receiving key. The last 32 bytes past a note's length stand in for
//! the leaf it is checked against.

use crate::keys::ReceiveKey;
use crate::notes::{open_xwing, BLOB_LEN};

const SEED: [u8; 64] = [7u8; 64];

pub fn note(bytes: &[u8]) {
    let blob = bytes.get(..BLOB_LEN).unwrap_or(bytes);
    let mut leaf = [0u8; 32];
    for (slot, byte) in leaf.iter_mut().zip(bytes.iter().skip(BLOB_LEN)) {
        *slot = *byte;
    }
    let key = ReceiveKey::from_seed(&SEED);
    let _ = open_xwing(blob, key.dk(), &leaf, &[1, 2, 3, 4]);
}
