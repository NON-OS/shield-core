//! One pass over the pool's history over Tor, in 10,000-block pages, accepted only whole: leaves
//! `0..nextLeafIndex` at one block, since a short history would show a balance missing notes.

use crate::discovery::{first_gap, note_commitments, Log};
use crate::error::NetError;
use crate::net::pool::{ACTIVE, NOTE_COMMITTED, NULLIFIER_SPENT, OUTPUT_NOTE, ROOT_COMMITTED};
use crate::net::rpc::{calls_at_over_tor, head_over_tor, pages_over_tor, RawLog};
use crate::net::tor::{Purpose, Tor};

/// `nextLeafIndex()`, from the compiled pool's method table.
const NEXT_LEAF_INDEX: [u8; 4] = [0x0b, 0xe4, 0xf4, 0x22];
const WINDOW: u64 = 10_000;

/// The pool's three event histories, whole, from the first RPC that serves them so.
pub struct History {
    pub head: u64,
    pub committed: Vec<RawLog>,
    pub outputs: Vec<RawLog>,
    pub nullifiers: Vec<RawLog>,
    /// Every `RootCommitted`, for anchoring a spend to the newest root.
    pub roots: Vec<RawLog>,
    /// The newest roots the association registry holds, or none when the pool has no registry.
    pub registered: Option<Vec<[u8; 32]>>,
}

/// Fetch the history, refusing any RPC whose leaves are not all of `0..n`.
pub fn fetch_history(tor: &Tor, hosts: &[&str]) -> Result<History, NetError> {
    let mut last = NetError::Transport;
    for host in hosts {
        match fetch_from(tor, host) {
            Ok(h) => return Ok(h),
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn fetch_from(tor: &Tor, host: &str) -> Result<History, NetError> {
    let head = head_over_tor(tor, host)?;
    let next = calls_at_over_tor(
        tor,
        Purpose::Scan,
        host,
        ACTIVE.address,
        &[NEXT_LEAF_INDEX.to_vec()],
        head,
    )?;
    let next_leaf = next.first().and_then(|w| w.get(24..32)).ok_or(NetError::ReplyShape)?;
    let mut be = [0u8; 8];
    be.copy_from_slice(next_leaf);
    let expected = u64::from_be_bytes(be);
    let pages =
        |topic| pages_over_tor(tor, host, ACTIVE.address, topic, ACTIVE.deploy_block, head, WINDOW);
    let committed = pages(NOTE_COMMITTED)?;
    let logs: Vec<Log> =
        committed.iter().map(|r| Log { topics: &r.topics, data: &r.data }).collect();
    let leaves = note_commitments(&logs);
    // Whole, or refused: no hole, and every leaf the pool says it holds.
    if first_gap(&leaves).is_some() || u64::try_from(leaves.len()).ok() != Some(expected) {
        return Err(NetError::ReplyShape);
    }
    let roots = pages(ROOT_COMMITTED)?;
    let registered = super::registry::registered(tor, host, &roots, head)?;
    Ok(History {
        head,
        committed,
        outputs: pages(OUTPUT_NOTE)?,
        nullifiers: pages(NULLIFIER_SPENT)?,
        roots,
        registered,
    })
}
