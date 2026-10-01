// NONOS Operating System (AGPL-3.0-or-later)

//! The `Air` and `AirExt` shape of the value-balance region: width seven, a two-row window,
//! six transition constraints of degree at most two, and both sums starting at zero.

use super::super::super::field::{Fp, Fp2};
use super::super::spec::{Air, AirExt};
use super::air::{ValueBalance, WIDTH};
use alloc::vec;
use alloc::vec::Vec;

impl Air for ValueBalance {
    fn log_trace_len(&self) -> u32 {
        self.log_t
    }

    fn trace_width(&self) -> usize {
        WIDTH
    }

    fn window_size(&self) -> usize {
        2
    }

    fn constraint_degree(&self) -> usize {
        2
    }

    fn num_transition(&self) -> usize {
        6
    }

    fn periodic_columns(&self) -> Vec<Vec<Fp>> {
        vec![self.signs(), self.closes()]
    }

    fn transition(&self, window: &[Fp], periodic: &[Fp]) -> Vec<Fp> {
        self.transition_impl(window, periodic)
    }

    fn boundary(&self) -> Vec<(usize, usize, Fp)> {
        vec![(0, 0, Fp::ZERO), (4, 0, Fp::ZERO)]
    }
}

impl AirExt for ValueBalance {
    fn transition_ext(&self, window: &[Fp2], periodic: &[Fp2]) -> Vec<Fp2> {
        self.transition_impl(window, periodic)
    }
}
