// NONOS Operating System (AGPL-3.0-or-later)
//! The soundness point every inner is proved at, and the hash the recursion runs.

use crate::crypto::stark::air::{Poseidon, RATE};
use crate::crypto::stark::field::Fp;

pub const NQ: usize = crate::shield_params::inner::N_QUERIES;
pub const GRIND: u32 = crate::shield_params::inner::GRIND_BITS;
pub const EXTRA: u32 = crate::shield_params::inner::EXTRA_BLOWUP_BITS;

/// Deployment blowup, unless the environment lowers it for a wiring gate. The
/// gates test binding logic, which is rate-independent; re-proving the inner
/// at rate 1/16 to check a copy constraint made every debug iteration cost a
/// quarter hour. Emits and vectors never set this.
pub fn extra() -> u32 {
    std::env::var("NONOS_INNER_EXTRA")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(EXTRA)
}

/// The recursion hash. Must equal the round count every in circuit compression
/// runs, or the membership regions prove a permutation the hash never computed.
pub const LOG_ROUNDS: u32 = 5;

pub fn hasher() -> Poseidon {
    Poseidon::new(LOG_ROUNDS, [Fp::ZERO; RATE])
}
