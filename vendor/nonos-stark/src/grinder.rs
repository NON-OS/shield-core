// NONOS Operating System (AGPL-3.0-or-later)

//! A grind search the host may supply, such as a browser's GPU. The prover
//! asks it first and checks what it returns: a nonce that does not meet the
//! work is dropped and the search runs here, so a faulty grinder can cost time
//! and never a proof. A grinder that returns the smallest nonce meeting the
//! work, as this one's searches do, leaves the proof's bytes unchanged.

use core::sync::atomic::{AtomicUsize, Ordering};

/// The smallest nonce whose grinding word has `bits` leading zeros against the
/// keccak template's lanes, or `None` to search here instead.
pub type Grinder = fn(&[u64; 25], u32) -> Option<u64>;

static GRINDER: AtomicUsize = AtomicUsize::new(0);

/// Use `g` for every grind from now on.
pub fn set_grinder(g: Grinder) {
    GRINDER.store(g as usize, Ordering::SeqCst);
}

/// Stop using a supplied grinder.
pub fn clear_grinder() {
    GRINDER.store(0, Ordering::SeqCst);
}

/// The supplied grinder's nonce for `template`, when there is one and it meets the work.
pub(crate) fn supplied(template: &[u64; 25], bits: u32) -> Option<u64> {
    let raw = GRINDER.load(Ordering::SeqCst);
    if raw == 0 {
        return None;
    }
    // SAFETY: only `set_grinder` stores a non-zero value, and it stores a `Grinder`.
    let g: Grinder = unsafe { core::mem::transmute::<usize, Grinder>(raw) };
    g(template, bits).filter(|&n| meets(template, n, bits))
}

/// Whether `nonce` meets `bits` of work against the template, as the prover checks it.
pub fn meets(template: &[u64; 25], nonce: u64, bits: u32) -> bool {
    crate::hash::pow_lane(template, nonce).leading_zeros() >= bits
}
