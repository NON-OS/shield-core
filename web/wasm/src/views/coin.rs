use nox_shield_core::net::asset::Coin;

pub fn coin(coin: Coin) -> &'static str {
    match coin {
        Coin::Eth => "eth",
        Coin::Nox => "nox",
        Coin::Usdc => "usdc",
    }
}
