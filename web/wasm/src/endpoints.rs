use crate::json::{list, text};
use nox_shield_core::evm::Network;
use nox_shield_core::net::pool::RPCS;
use wasm_bindgen::prelude::wasm_bindgen;

/// Every host the core may send a request to, as a JSON list: the pool's endpoints and the public
/// account's, for reading and for sending, on both networks. The release build writes the page's
/// Content Security Policy from this, so the browser refuses any other.
#[wasm_bindgen]
pub fn endpoint_hosts() -> String {
    let mut hosts: Vec<&str> = RPCS.to_vec();
    for network in [Network::Mainnet, Network::Sepolia] {
        let chain = network.chain();
        hosts.extend(chain.rpcs);
        hosts.extend(chain.send_rpcs);
    }
    hosts.sort_unstable();
    hosts.dedup();
    list(hosts.into_iter().map(text))
}
