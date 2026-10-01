// NONOS Operating System (AGPL-3.0-or-later)

//! A running-sum accumulator AIR: two columns, a running total and a per-row
//! addend, with `acc[i+1] = acc[i] + addend[i]`, pinned to zero at the first and
//! last rows. It proves that the addends sum to zero, the additive conservation a
//! value-balance argument rests on (signed inputs and outputs cancel). Written
//! once over the `Felt` abstraction, so it is proven at money-grade soundness by
//! `stark_prove_ext`. Constraint degree one, so the domain stays small.

use super::super::field::{Felt, Fp, Fp2};
use super::spec::{Air, AirExt};
use alloc::vec;
use alloc::vec::Vec;

pub struct Accumulator {
    pub log_t: u32,
}

impl Accumulator {
    /// One transition, over any field: the next running total is the current one
    /// plus this row's addend. `window = [acc_i, addend_i, acc_next, addend_next]`.
    fn transition_impl<F: Felt>(&self, window: &[F], _periodic: &[F]) -> Vec<F> {
        vec![window[2] - window[0] - window[1]]
    }
}

impl Air for Accumulator {
    fn log_trace_len(&self) -> u32 {
        self.log_t
    }

    fn trace_width(&self) -> usize {
        2
    }

    fn window_size(&self) -> usize {
        2
    }

    fn constraint_degree(&self) -> usize {
        1
    }

    fn num_transition(&self) -> usize {
        1
    }

    fn transition(&self, window: &[Fp], periodic: &[Fp]) -> Vec<Fp> {
        self.transition_impl(window, periodic)
    }

    fn boundary(&self) -> Vec<(usize, usize, Fp)> {
        // The running total starts and ends at zero: the addends sum to zero.
        let last = (1usize << self.log_t) - 1;
        vec![(0, 0, Fp::ZERO), (0, last, Fp::ZERO)]
    }
}

impl AirExt for Accumulator {
    fn transition_ext(&self, window: &[Fp2], periodic: &[Fp2]) -> Vec<Fp2> {
        self.transition_impl(window, periodic)
    }
}
