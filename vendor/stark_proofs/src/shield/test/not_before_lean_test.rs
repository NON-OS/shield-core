// NONOS Operating System (AGPL-3.0-or-later)
//! The Lean model of word 36 and the Rust constants name the same numbers.
//! `lean/Shield/NotBefore.lean` proves the layout and the grid rule over its
//! own constants; this reads them out of the file, so a change on either side
//! without the other fails here.
#![cfg(test)]

use crate::shield::join::publics::{FEE_RECIPIENT, NOT_BEFORE, NOT_BEFORE_GRID_S};

const LEAN: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../lean/Shield/NotBefore.lean"
));

fn lean_def(name: &str) -> u64 {
    let key = format!("def {name} : Nat := ");
    let at = LEAN
        .find(&key)
        .unwrap_or_else(|| panic!("{name} is not defined in NotBefore.lean"));
    LEAN[at + key.len()..]
        .split_whitespace()
        .next()
        .and_then(|v| v.parse().ok())
        .expect("a number")
}

#[test]
fn the_lean_layout_is_the_rust_layout() {
    assert_eq!(lean_def("positionOfNotBefore"), NOT_BEFORE as u64);
    assert_eq!(lean_def("positionOfFeeRecipient"), FEE_RECIPIENT as u64);
    assert_eq!(lean_def("grid"), NOT_BEFORE_GRID_S);
}
