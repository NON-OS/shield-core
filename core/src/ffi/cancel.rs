//! The cancellation handle a shell holds while a proof runs.
//!
//! Proving is the only long call in the app, so the UI needs a way to stop it
//! that does not kill a thread mid allocation. The token is checked at the
//! prover's stage boundaries.

use crate::prover::Cancel;

/// A cancellation handle the shells hold while a proof runs.
#[derive(uniffi::Object)]
pub struct CancelToken {
    inner: Cancel,
}

#[uniffi::export]
impl CancelToken {
    /// A fresh token, not yet cancelled.
    #[uniffi::constructor]
    pub fn new() -> std::sync::Arc<CancelToken> {
        std::sync::Arc::new(CancelToken { inner: Cancel::new() })
    }

    /// Ask the running proof to stop at its next stage boundary.
    pub fn cancel(&self) {
        self.inner.cancel();
    }

    /// Whether cancellation has been asked for.
    pub fn cancelled(&self) -> bool {
        self.inner.cancelled()
    }
}

impl CancelToken {
    pub(super) fn token(&self) -> &Cancel {
        &self.inner
    }
}
