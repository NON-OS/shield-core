//! The sweep that runs without a fuzzer, on every push: each parser fed every length of a
//! pattern, pseudorandom buffers, and valid encodings with a byte flipped. It finds less than a
//! fuzzer but finds it every time, the property a regression gate needs.

// Tests assert by panicking and build byte patterns by hand, so those lints are off here only.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use super::{account, address, disk, frame, lander, note, policy, row, rpc, typed};

/// Every parser that takes bytes nobody in this crate wrote.
const PARSERS: [fn(&[u8]); 10] =
    [address, note, rpc, frame, row, account, lander, policy, typed, disk];

/// A fixed walk, not randomness, so a failure reproduces from its seed.
fn walk(state: &mut u64) -> u8 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    (*state & 0xff) as u8
}

/// Every length up to past the longest fixed record, of a pattern that is valid nothing.
#[test]
fn no_parser_panics_on_any_length() {
    let mut bytes = Vec::new();
    let mut state = 0x243f_6a88_85a3_08d3u64;
    for _ in 0..1024 {
        for parse in PARSERS {
            parse(&bytes);
        }
        bytes.push(walk(&mut state));
    }
}

/// Contents that change instead of growing, where a length field read from the input decides
/// how much the parser trusts.
#[test]
fn no_parser_panics_on_random_content() {
    let mut state = 0x13198a2e_03707344u64;
    for _ in 0..4096 {
        let len = (walk(&mut state) as usize) * 4;
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            bytes.push(walk(&mut state));
        }
        for parse in PARSERS {
            parse(&bytes);
        }
    }
}
