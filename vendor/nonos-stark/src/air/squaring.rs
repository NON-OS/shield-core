// NONOS Operating System (AGPL-3.0-or-later)

//! The squaring AIR: a chain `t[i+1] = t[i]^2` from a public seed.

use super::super::field::{Felt, Fp, Fp2};
use super::spec::{Air, AirExt};
use alloc::vec;
use alloc::vec::Vec;

pub struct Squaring {
    pub log_t: u32,
    pub seed: Fp,
}

impl Squaring {
    fn transition_impl<F: Felt>(&self, window: &[F], _periodic: &[F]) -> Vec<F> {
        vec![window[1] - window[0] * window[0]]
    }
}

impl AirExt for Squaring {
    fn transition_ext(&self, window: &[Fp2], periodic: &[Fp2]) -> Vec<Fp2> {
        self.transition_impl(window, periodic)
    }
}

impl Air for Squaring {
    fn log_trace_len(&self) -> u32 {
        self.log_t
    }

    fn trace_width(&self) -> usize {
        1
    }

    fn window_size(&self) -> usize {
        2
    }

    fn constraint_degree(&self) -> usize {
        2
    }

    fn num_transition(&self) -> usize {
        1
    }

    fn transition(&self, window: &[Fp], periodic: &[Fp]) -> Vec<Fp> {
        self.transition_impl(window, periodic)
    }

    fn boundary(&self) -> Vec<(usize, usize, Fp)> {
        // column 0, row 0, the public seed.
        vec![(0, 0, self.seed)]
    }
}
