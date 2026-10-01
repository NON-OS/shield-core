//! The policy and lander replies a fuzzer reaches. Built only with `fuzzing`.

pub fn policy(bytes: &[u8]) {
    let _ = super::fee_schedule::schedule(bytes);
    let _ = super::fee_schedule::bps(bytes);
}

pub fn lander(status: u16, body: &str) {
    super::relay::fuzz_hook::replies(status, body);
}
