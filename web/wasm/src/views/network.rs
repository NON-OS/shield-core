use nox_shield_core::evm::Network;

pub fn network(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Sepolia => "sepolia",
    }
}
