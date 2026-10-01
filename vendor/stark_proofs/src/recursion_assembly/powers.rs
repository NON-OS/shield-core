// NONOS Operating System (AGPL-3.0-or-later)
//! The two powers regions: the composition coefficients as powers of the
//! alpha the transcript squeezed for them, and the DEEP coefficients as
//! powers of theirs. Four columns each; the alpha cell is bound to its
//! squeeze and every power cell to the consumer that carries it.

use crate::crypto::stark::air::AlphaPowers;
use crate::crypto::stark::field::{Fp, Fp2};
use alloc::vec::Vec;

/// The powers region over `alpha` for `n` coefficients and its trace. `held`
/// is the vector the consumer carries on an honest assembly; it is these
/// powers or the wiring refuses the witness after the whole assembly, so it
/// is refused here by name instead. A tampered assembly passes `None`: the
/// bent coefficient is exactly what the wiring must catch.
pub fn powers_region(
    alpha: Fp2,
    n: usize,
    held: Option<&[Fp2]>,
    what: &str,
) -> (AlphaPowers, Vec<Fp>) {
    let region = AlphaPowers::new(alpha, n);
    if let Some(held) = held {
        assert!(
            region.powers() == held,
            "the {what} are not the powers of the alpha the transcript squeezed for them"
        );
    }
    let trace = region.trace();
    (region, trace)
}
