//! The pool's history kept between passes, so the next pass reads only the blocks since. Only logs
//! `SETTLED` blocks or more under the head they were read at are kept, so a tip the chain
//! reorganises is always read again, and a pass still accepts the joined history only whole.

use super::sync_chain::History;
use crate::net::rpc::RawLog;
use std::sync::Mutex;

/// Blocks under the head that a kept log must be, well past any reorganisation Ethereum sees.
const SETTLED: u64 = 64;

/// The logs of the four histories up to `upto`, as one host served them for one pool.
#[derive(Clone)]
pub(super) struct Kept {
    host: String,
    pool: &'static str,
    pub upto: u64,
    pub committed: Vec<RawLog>,
    pub outputs: Vec<RawLog>,
    pub nullifiers: Vec<RawLog>,
    pub roots: Vec<RawLog>,
}

static KEPT: Mutex<Option<Kept>> = Mutex::new(None);

impl Kept {
    /// Nothing kept: every history read from the pool's first block.
    pub(super) fn none() -> Kept {
        Kept {
            host: String::new(),
            pool: "",
            upto: 0,
            committed: Vec::new(),
            outputs: Vec::new(),
            nullifiers: Vec::new(),
            roots: Vec::new(),
        }
    }
}

/// What is kept for `pool` from `host`, if anything.
pub(super) fn kept(host: &str, pool: &'static str) -> Option<Kept> {
    let k = KEPT.lock().ok()?;
    k.as_ref().filter(|k| k.host == host && k.pool == pool).cloned()
}

/// Keep the settled part of a whole history.
pub(super) fn keep(host: &str, pool: &'static str, h: &History) {
    let upto = h.head.saturating_sub(SETTLED);
    let settled = |logs: &[RawLog]| logs.iter().filter(|l| l.block <= upto).cloned().collect();
    let k = Kept {
        host: host.to_string(),
        pool,
        upto,
        committed: settled(&h.committed),
        outputs: settled(&h.outputs),
        nullifiers: settled(&h.nullifiers),
        roots: settled(&h.roots),
    };
    if let Ok(mut slot) = KEPT.lock() {
        *slot = Some(k);
    }
}

/// Forget what is kept, after a joined history was refused.
pub(super) fn forget() {
    if let Ok(mut slot) = KEPT.lock() {
        *slot = None;
    }
}
