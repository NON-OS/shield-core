//! Which multiply this build uses. The portable fold runs everywhere unless the `kernel` feature
//! is on for aarch64, so no build silently takes assembly it was not measured with.

use super::portable;
use super::ring;

/// The field multiply in use.
#[inline]
pub fn mul(a: u64, b: u64) -> u64 {
    #[cfg(all(feature = "kernel", target_arch = "aarch64"))]
    {
        super::aarch64::mul(a, b)
    }
    #[cfg(not(all(feature = "kernel", target_arch = "aarch64")))]
    {
        portable::mul(a, b)
    }
}

/// Addition and subtraction have no kernel: the compiler already emits three instructions.
#[inline]
pub fn add(a: u64, b: u64) -> u64 {
    ring::add(a, b)
}

#[inline]
pub fn sub(a: u64, b: u64) -> u64 {
    ring::sub(a, b)
}

/// Which multiply this build uses, for a bench to report.
pub fn kernel_in_use() -> &'static str {
    if cfg!(all(feature = "kernel", target_arch = "aarch64")) {
        "aarch64 assembly"
    } else {
        "portable"
    }
}
