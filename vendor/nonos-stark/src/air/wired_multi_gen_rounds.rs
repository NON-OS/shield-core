// NONOS Operating System (AGPL-3.0-or-later)
//! The generic wired engine as a two round AIR.
//!
//! `WiredMultiGen` holds the engine and a typed region list beside it. Only the
//! engine knows where the permutation columns start and how to fill them, so
//! all three of these delegate. The typed list plays no part: it exists so the
//! recursion can recompute a region's transition over the tower, which is not
//! something a commitment round touches.
//!
//! Without this the deployed circuit cannot be proved in two rounds, and the
//! copy constraint inside it is argued at a point the prover chose. Generic
//! over the region list for the same reason the wrapper is: the settlement
//! outer proves in two rounds too, and a wrap over it verifies both.

use super::gen_region::GenRegion;
use super::rounds::Permuted;
use super::super::field::{Fp, Fp2};
use super::wired_multi_gen::WiredMultiGen;

impl<R: GenRegion + Send + Sync> Permuted for WiredMultiGen<R> {
    fn region_width(&self) -> usize {
        self.wired().region_width()
    }

    fn set_challenges(&mut self, beta: Fp, gamma: Fp) {
        self.wired_mut().set_challenges(beta, gamma)
    }

    fn set_challenges_ext(&mut self, beta: Fp2, gamma: Fp2) {
        self.wired_mut().set_challenges_ext(beta, gamma)
    }

    fn fill_products(&self, trace: &mut [Fp]) {
        self.wired().refill_products(trace)
    }
}
