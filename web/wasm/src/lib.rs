// NOX Shield web core.
// Copyright (C) 2026 NONOS Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The wallet core and the prover, for a page. The prover's exports come from `nox_prover`
//! itself, so a browser runs the code the phones run; what is added here is what the page needs
//! to check it is talking to the build it expects.

#[cfg(feature = "panic-report")]
mod panic_report;
mod periodic_root;

#[cfg(feature = "panic-report")]
pub use panic_report::report_panics;
pub use periodic_root::periodic_root;
