//! The typed EVM address and amount of each coin a fuzzer reaches. Built only with `fuzzing`.

use crate::net::asset::Coin;

pub fn typed(text: &str) {
    let _ = super::evm::parse_evm_address(text);
    for coin in [Coin::Eth, Coin::Nox, Coin::Usdc] {
        let _ = super::amount_read::parse_amount(coin, text.to_string());
    }
}
