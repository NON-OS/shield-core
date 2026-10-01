// NONOS Operating System (AGPL-3.0-or-later)
//! The Lean model of the claim's two words and the Rust constants name the
//! same numbers. `lean/Shield/Claim.lean` proves the layout and the
//! reconstruction over its own constants; this reads them out of the file.
#![cfg(test)]

use crate::shield::join::publics::{INPUT_SUM_HI, INPUT_SUM_LO};

const LEAN: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../lean/Shield/Claim.lean"
));

fn lean_def(name: &str) -> u64 {
    let key = format!("def {name} : Nat := ");
    let at = LEAN
        .find(&key)
        .unwrap_or_else(|| panic!("{name} is not defined in Claim.lean"));
    LEAN[at + key.len()..]
        .split_whitespace()
        .next()
        .and_then(|v| v.parse().ok())
        .expect("a number")
}

#[test]
fn the_lean_claim_layout_is_the_rust_layout() {
    assert_eq!(lean_def("positionOfInputSumLo"), INPUT_SUM_LO as u64);
    assert_eq!(lean_def("positionOfInputSumHi"), INPUT_SUM_HI as u64);
    // the split `join::terms` makes: low limb `v & 0xFFFF_FFFF`, high `v >> 32`
    let v: u64 = 0x0123_4567_89AB_CDEF;
    let shift = lean_def("limbShift");
    assert_eq!((v & 0xFFFF_FFFF) + (v >> 32) * shift, v);
    assert_eq!(shift, 1 << 32);
}
