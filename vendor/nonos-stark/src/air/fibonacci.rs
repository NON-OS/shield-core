// NONOS Operating System (AGPL-3.0-or-later)

//! The Fibonacci AIR: `t[i+2] = t[i+1] + t[i]` from `t[0] = t[1] = 1`. A second,
//! structurally different computation, proven by the same engine as squaring,
//! which is what shows the AIR layer is general and not fitted to one problem.

use super::super::field::{Felt, Fp, Fp2};
use super::spec::{Air, AirExt};
use alloc::vec;
use alloc::vec::Vec;

pub struct Fibonacci {
    pub log_t: u32,
}

impl Fibonacci {
    /// The transition written once over any field, so it serves both the base
    /// composition and the extension out-of-domain evaluation.
    fn transition_impl<F: Felt>(&self, window: &[F], _periodic: &[F]) -> Vec<F> {
        // f(g^2*x) - f(g*x) - f(x)
        vec![window[2] - window[1] - window[0]]
    }
}

impl Air for Fibonacci {
    fn log_trace_len(&self) -> u32 {
        self.log_t
    }

    fn trace_width(&self) -> usize {
        1
    }

    fn window_size(&self) -> usize {
        3
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
        // column 0, the first two rows are both one.
        vec![(0, 0, Fp::ONE), (0, 1, Fp::ONE)]
    }
}

impl AirExt for Fibonacci {
    fn transition_ext(&self, window: &[Fp2], periodic: &[Fp2]) -> Vec<Fp2> {
        self.transition_impl(window, periodic)
    }
}
