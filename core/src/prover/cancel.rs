//! The cancellation flag a shell holds while a proof runs.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Cooperative cancellation, checked at stage boundaries in `run`, and a cancelled proof is
/// dropped. No stage is cut part way, since killing a prover mid allocation corrupts the store.
#[derive(Clone, Default)]
pub struct Cancel {
    flag: Arc<AtomicBool>,
}

impl Cancel {
    /// A fresh token, not yet cancelled.
    pub fn new() -> Cancel {
        Cancel::default()
    }

    /// Ask for cancellation. Safe to call from any thread, including the UI one.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    /// The flag itself, for a prover that polls it between phases.
    pub(crate) fn flag(&self) -> &AtomicBool {
        &self.flag
    }

    /// Whether cancellation has been asked for.
    pub fn cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}
