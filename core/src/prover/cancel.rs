//! The cancellation flag a shell holds while a proof runs, and where the proof reports its phases.

use nox_prover::Phase;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Called at each phase boundary with the phase just finished and the share of the proof done.
pub type Progress = Arc<dyn Fn(Phase, f32) + Send + Sync>;

/// Cooperative cancellation, checked at stage boundaries in `run`, and a cancelled proof is
/// dropped. No stage is cut part way, since killing a prover mid allocation corrupts the store.
#[derive(Clone, Default)]
pub struct Cancel {
    flag: Arc<AtomicBool>,
    progress: Option<Progress>,
}

impl Cancel {
    /// A fresh token, not yet cancelled.
    pub fn new() -> Cancel {
        Cancel::default()
    }

    /// A fresh token whose proof reports each phase it finishes to `progress`.
    pub fn with_progress(progress: Progress) -> Cancel {
        Cancel { flag: Arc::default(), progress: Some(progress) }
    }

    /// Ask for cancellation. Safe to call from any thread, including the UI one.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    /// The flag itself, for a prover that polls it between phases.
    pub(crate) fn flag(&self) -> &AtomicBool {
        &self.flag
    }

    /// The phase observer, for a prover that reports between phases.
    pub(crate) fn progress(&self) -> Option<&(dyn Fn(Phase, f32) + Sync)> {
        self.progress.as_deref().map(|p| p as &(dyn Fn(Phase, f32) + Sync))
    }

    /// Whether cancellation has been asked for.
    pub fn cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}
