#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    nox_shield_core::fuzz::policy(data);
});
