// NOX Shield field kernel.
// Copyright (C) 2026 NONOS Contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The Goldilocks multiply inside the prover's transform, in portable Rust and aarch64
//! assembly, with a differential test that they agree. It is not wired into the vendored
//! prover: changing a trust path is measured and asked for first, as `README.md` describes.

#![cfg_attr(not(test), no_std)]

#[cfg(all(feature = "kernel", target_arch = "aarch64"))]
mod aarch64;
mod butterfly;
mod consts;
mod dispatch;
mod portable;
mod ring;

pub use butterfly::butterfly;
pub use consts::{EPSILON, P};
pub use dispatch::{add, kernel_in_use, mul, sub};

/// The reference implementations, for tests and readers to compare the kernel against.
pub mod reference {
    pub use super::portable::{canonical, mul, reduce128};
    pub use super::ring::{add, sub};
}

#[cfg(all(feature = "kernel", target_arch = "aarch64"))]
pub mod kernel {
    pub use super::aarch64::mul;
}
