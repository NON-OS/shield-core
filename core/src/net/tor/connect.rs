//! Opening a stream: on the circuits of its purpose, and of the active account unless it is a
//! scan. Onion services are allowed and given the longer limit a rendezvous needs.

use super::{stream, Purpose, Tor, TorStream, ONION_CONNECT};
use crate::error::NetError;
use arti_client::config::BoolOrAuto;
use arti_client::StreamPrefs;

impl Tor {
    /// A stream on circuits reserved for `purpose`, resolved at the exit. A failure is
    /// returned and never retried on a direct connection.
    pub fn connect(&self, purpose: Purpose, host: &str, port: u16) -> Result<TorStream, NetError> {
        // A fresh onion rendezvous is slower than an exit connection, so it gets a longer limit.
        let limit = if host.ends_with(".onion") { ONION_CONNECT } else { stream::STALL };
        self.connect_within(purpose, (host, port), limit)
    }

    /// `connect`, given up after `limit`, for a caller with its own time to keep.
    pub fn connect_within(
        &self,
        purpose: Purpose,
        (host, port): (&str, u16),
        limit: std::time::Duration,
    ) -> Result<TorStream, NetError> {
        let client = match purpose {
            Purpose::Scan => &self.scan,
            Purpose::Relay => &self.relay,
            Purpose::Deposit => &self.deposit,
            Purpose::Mainnet => &self.mainnet,
            Purpose::Sepolia => &self.sepolia,
        };
        let mut prefs = StreamPrefs::new();
        prefs.connect_to_onion_services(BoolOrAuto::Explicit(true));
        if purpose != Purpose::Scan {
            prefs.set_isolation(self.accounts.token());
        }
        let connect = client.connect_with_prefs((host, port), &prefs);
        let inner = self
            .rt
            .block_on(async { tokio::time::timeout(limit, connect).await })
            .map_err(|_| NetError::Transport)?
            .map_err(|_| NetError::ProxyRefused)?;
        Ok(TorStream::new(self.rt.handle().clone(), inner))
    }
}
