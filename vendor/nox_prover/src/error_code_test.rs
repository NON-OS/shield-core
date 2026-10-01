// NONOS Operating System (AGPL-3.0-or-later)
//! Every prover error has its own stable code, and the C constants name the
//! same numbers. A wallet maps these one to one, so a renumbering or a shared
//! code would show a user the wrong message.

use crate::Error;

fn every_kind() -> [Error; 8] {
    [
        Error::Request(String::new()),
        Error::Policy(String::new()),
        Error::Entropy(String::new()),
        Error::Cache(String::new()),
        Error::Circuit(String::new()),
        Error::NotVerified(String::new()),
        Error::Cancelled,
        Error::Rank(String::new()),
    ]
}

#[test]
fn every_error_code_is_distinct_and_nonzero() {
    let codes: Vec<i32> = every_kind().iter().map(Error::code).collect();
    for (i, c) in codes.iter().enumerate() {
        assert_ne!(*c, 0, "0 means success");
        assert!(!codes[i + 1..].contains(c), "code {c} is shared");
    }
}

/// The numbers themselves, pinned: a change here breaks every wallet build.
#[test]
fn the_codes_are_the_published_numbers() {
    let codes: Vec<i32> = every_kind().iter().map(Error::code).collect();
    assert_eq!(codes, [1, 2, 3, 4, 5, 6, 7, 9]);
}

#[test]
fn the_c_constants_name_the_same_numbers() {
    use crate::ffi::*;
    let named = [
        NOX_ERR_REQUEST,
        NOX_ERR_POLICY,
        NOX_ERR_ENTROPY,
        NOX_ERR_CACHE,
        NOX_ERR_CIRCUIT,
        NOX_ERR_NOT_VERIFIED,
        NOX_ERR_CANCELLED,
        NOX_ERR_RANK,
    ];
    let codes: Vec<i32> = every_kind().iter().map(Error::code).collect();
    assert_eq!(codes, named);
}
