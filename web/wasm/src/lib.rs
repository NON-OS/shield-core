// NOX Shield web core.
// Copyright (C) 2026 NONOS Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The wallet core and the prover, for a page. The page's worker holds the native `Wallet` and
//! calls it by name; the prover's own exports come from `nox_prover`, so a browser runs the code
//! the phones run.

mod calls;
mod endpoints;
mod guard;
mod json;
#[cfg(feature = "panic-report")]
mod panic_report;
mod periodic_cache;
mod periodic_root;
mod progress;
mod views;
mod wallet;

pub use endpoints::endpoint_hosts;
#[cfg(feature = "panic-report")]
pub use panic_report::report_panics;
pub use periodic_cache::periodic_cache;
pub use periodic_root::periodic_root;
pub use progress::prove_reporting;
pub use wallet::{changed_files, load_file, read_file, WebWallet};
