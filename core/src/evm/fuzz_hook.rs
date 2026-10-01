//! The readers of the public account a fuzzer reaches: replies, a block, a nonce line and a swap
//! market. Built only with `fuzzing`.

use super::reply::{batch, one};

pub fn reply(text: &str) {
    for n in [1, 6] {
        for answer in batch(text, n).unwrap_or_default() {
            let _ = (answer.quantity(), answer.word(), answer.data(), answer.result());
        }
    }
    if let Ok(answer) = one(text) {
        let _ = (answer.quantity(), answer.word(), answer.data(), super::gas::timestamp(&answer));
    }
    let _ = super::gas::base_fee(text);
    let _ = super::nonce::line(text);
    super::swap::fuzz_hook::market(text);
}
