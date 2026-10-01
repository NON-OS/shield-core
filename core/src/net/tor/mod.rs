//! The wallet's own Tor client, which checks the directory signatures and picks its own path.
//! Each purpose has its own circuits, so a scan exit never carries a hand-off. Guards persist
//! against rotation onto a hostile guard, and vanguards protect onion circuits.

mod account;
pub use account::as_account;
mod connect;
mod stream;
mod tls;

pub use stream::TorStream;
pub use tls::tls;

use crate::error::NetError;
use arti_client::config::TorClientConfigBuilder;
use arti_client::TorClient as Client;
use arti_client::TorClient;
use std::path::Path;
use tokio::runtime::Runtime;
use tor_rtcompat::PreferredRuntime;

const ONION_CONNECT: std::time::Duration = std::time::Duration::from_secs(120);

/// What a connection is for. Each gets circuits no other purpose shares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    Scan,
    Relay,
    /// Pool reads for a deposit. They name the user's EVM address.
    Deposit,
    /// The public account on mainnet, apart from the pool and the other network.
    Mainnet,
    Sepolia,
}

pub struct Tor {
    rt: Runtime,
    scan: std::sync::Arc<Client<PreferredRuntime>>,
    relay: std::sync::Arc<Client<PreferredRuntime>>,
    deposit: std::sync::Arc<Client<PreferredRuntime>>,
    mainnet: std::sync::Arc<Client<PreferredRuntime>>,
    sepolia: std::sync::Arc<Client<PreferredRuntime>>,
    /// The circuits of each account, apart from every other account's.
    accounts: account::Accounts,
}

impl Tor {
    /// Bootstrap with state under `dir`, so guards persist. An unreachable network reports
    /// `ProxyUnreachable`, the sentence the shells already show.
    pub fn start(dir: &Path) -> Result<Tor, NetError> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| NetError::Transport)?;
        let config = TorClientConfigBuilder::from_directories(dir.join("state"), dir.join("cache"))
            .build()
            .map_err(|_| NetError::ProxyRefused)?;
        let base = rt
            .block_on(TorClient::create_bootstrapped(config))
            .map_err(|_| NetError::ProxyUnreachable)?;
        Ok(Tor {
            scan: base.isolated_client(),
            relay: base.isolated_client(),
            deposit: base.isolated_client(),
            mainnet: base.isolated_client(),
            sepolia: base.isolated_client(),
            accounts: account::Accounts::default(),
            rt,
        })
    }
}
