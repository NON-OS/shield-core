//! The landers of a pool, tried in order over Tor, each used only when `/v1/info` names the pool and
//! takes the submitter fee. One that fails, names another pool or refuses is passed over, a refusal
//! shown only when every lander gave one. The pool lands a proof once, whoever reaches it.

use super::{ask, hand, reply, Handed};
use crate::error::NetError;
use crate::net::pool::Lander;
use crate::net::tor::Tor;

/// The first lander in `landers` that queues the hand-off `json` for `pool`, or the last refusal
/// when none queues it.
pub fn hand_first(
    tor: &Tor,
    landers: &[Lander],
    pool: &str,
    json: &str,
) -> Result<(usize, Handed), NetError> {
    let mut last = Err(NetError::Transport);
    for (at, lander) in landers.iter().enumerate() {
        match ready(tor, lander.tor, pool).and_then(|_| hand(tor, lander.tor, json)) {
            Ok(Handed::Queued { id }) => return Ok((at, Handed::Queued { id })),
            Ok(refused) => last = Ok((at, refused)),
            Err(e) if last.is_err() => last = Err(e),
            Err(_) => {}
        }
    }
    last
}

/// Whether the lander at `onion` serves `pool` and takes the submitter fee, as one error if not.
fn ready(tor: &Tor, onion: &str, pool: &str) -> Result<(), NetError> {
    let (status, body) = ask(tor, onion, ("GET", "/v1/info"), None)?;
    let serves = reply::serves(&body, pool) && reply::takes_submitter_fee(&body);
    if status != 200 || !serves {
        return Err(NetError::WrongRelayer);
    }
    Ok(())
}

#[cfg(test)]
mod live {
    #![allow(clippy::expect_used)]
    use super::ready;
    use crate::net::pool::ACTIVE;
    use crate::net::tor::Tor;

    /// Every production lander answers over Tor for the production pool. Needs the network.
    #[test]
    #[ignore]
    fn every_lander_serves_the_pool_over_tor() {
        let tor = Tor::start(&std::env::temp_dir().join("nox-tor-landers")).expect("bootstrap");
        for lander in ACTIVE.landers {
            ready(&tor, lander.tor, ACTIVE.address).expect(lander.tor);
        }
    }
}
