// NONOS Operating System (AGPL-3.0-or-later)

//! The `Air` shape of the live gate: twenty one columns on one row, thirteen
//! constraints, degree two. Every constraint is a bit times a difference, so
//! the region costs one degree over the linear ones and forces nothing on the
//! blowup of an assembly that already carries a membership.

use super::super::super::field::{Fp, Fp2};
use super::super::spec::{Air, AirExt};
use super::air::{LiveGate, LANES};
use alloc::vec;
use alloc::vec::Vec;

impl Air for LiveGate {
    fn log_trace_len(&self) -> u32 {
        self.log_t
    }

    fn trace_width(&self) -> usize {
        LiveGate::WIDTH
    }

    fn window_size(&self) -> usize {
        2
    }

    fn constraint_degree(&self) -> usize {
        2
    }

    fn num_transition(&self) -> usize {
        5 + 2 * LANES
    }

    fn periodic_columns(&self) -> Vec<Vec<Fp>> {
        Vec::new()
    }

    fn transition(&self, window: &[Fp], periodic: &[Fp]) -> Vec<Fp> {
        self.transition_impl(window, periodic)
    }

    fn boundary(&self) -> Vec<(usize, usize, Fp)> {
        // Nothing is pinned. Every cell is bound by the assembly to the place
        // that computes it, which is what makes the gate a statement about the
        // spend rather than about numbers this region chose.
        vec![]
    }
}

impl AirExt for LiveGate {
    fn transition_ext(&self, window: &[Fp2], periodic: &[Fp2]) -> Vec<Fp2> {
        self.transition_impl(window, periodic)
    }
}
