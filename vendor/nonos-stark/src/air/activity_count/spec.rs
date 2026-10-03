// NONOS Operating System (AGPL-3.0-or-later)

use super::super::super::field::{Fp, Fp2};
use super::super::spec::{Air, AirExt};
use super::air::ActivityCount;
use alloc::vec;
use alloc::vec::Vec;

impl Air for ActivityCount {
    fn log_trace_len(&self) -> u32 {
        self.log_t
    }

    fn trace_width(&self) -> usize {
        ActivityCount::WIDTH
    }

    fn window_size(&self) -> usize {
        2
    }

    fn constraint_degree(&self) -> usize {
        2
    }

    fn num_transition(&self) -> usize {
        ActivityCount::CONSTRAINTS
    }

    fn periodic_columns(&self) -> Vec<Vec<Fp>> {
        Vec::new()
    }

    fn transition(&self, window: &[Fp], periodic: &[Fp]) -> Vec<Fp> {
        self.transition_impl(window, periodic)
    }

    fn boundary(&self) -> Vec<(usize, usize, Fp)> {
        vec![]
    }
}

impl AirExt for ActivityCount {
    fn transition_ext(&self, window: &[Fp2], periodic: &[Fp2]) -> Vec<Fp2> {
        self.transition_impl(window, periodic)
    }
}
