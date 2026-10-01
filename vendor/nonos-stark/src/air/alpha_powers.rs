// NONOS Operating System (AGPL-3.0-or-later)

//! The powers of one challenge, as a region.
//!
//! A transcript that squeezes a coefficient per term costs the wrap one
//! permutation per squeeze, and the outer has thousands of terms. Drawing
//! one challenge and taking its powers costs one squeeze and this region:
//! row i holds alpha^i beside alpha, the next row holds the product, and
//! the assembly wires row i to whoever consumes coefficient i. Four base
//! columns, four lanes of degree two, no periodic columns.
//!
//! Soundness is the same argument as independent coefficients: a nonzero
//! polynomial of degree n in alpha vanishes at a random alpha with
//! probability at most n over the field, and n is a few thousand against
//! 2^128.

use super::super::field::{Felt, Fp, Fp2};
use super::spec::{Air, AirExt};
use alloc::vec::Vec;

pub struct AlphaPowers {
    alpha: Fp2,
    n: usize,
    log_len: u32,
}

impl AlphaPowers {
    /// `n` powers, alpha^0 through alpha^(n-1).
    pub fn new(alpha: Fp2, n: usize) -> AlphaPowers {
        let log_len = n.max(2).next_power_of_two().trailing_zeros();
        AlphaPowers { alpha, n, log_len }
    }

    pub fn len(&self) -> usize {
        self.n
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    pub fn rows(&self) -> usize {
        1usize << self.log_len
    }

    /// The cell holding the low half of alpha^i; the high half is the next
    /// column.
    pub fn power_cell(&self, i: usize) -> (usize, usize) {
        (i, 0)
    }

    /// The cell holding the low half of alpha; the high half is the next
    /// column. Every row carries it and a lane keeps them equal, so the
    /// first row's is the one to wire.
    pub fn alpha_cell(&self) -> (usize, usize) {
        (0, 2)
    }

    pub fn powers(&self) -> Vec<Fp2> {
        let mut v = Vec::with_capacity(self.n);
        let mut p = Fp2::ONE;
        for _ in 0..self.n {
            v.push(p);
            p = p * self.alpha;
        }
        v
    }

    /// Padding rows keep multiplying, so every transition holds; the last
    /// row's successor is masked by the engine like every region's.
    pub fn trace(&self) -> Vec<Fp> {
        let rows = self.rows();
        let mut tr = alloc::vec![Fp::ZERO; rows * 4];
        let mut p = Fp2::ONE;
        for r in 0..rows {
            tr[r * 4] = p.c0;
            tr[r * 4 + 1] = p.c1;
            tr[r * 4 + 2] = self.alpha.c0;
            tr[r * 4 + 3] = self.alpha.c1;
            p = p * self.alpha;
        }
        tr
    }

    pub fn transition_gen<F: Felt>(&self, window: &[F], periodic: &[F]) -> Vec<F> {
        self.transition_impl(window, periodic)
    }

    fn transition_impl<F: Felt>(&self, w: &[F], _p: &[F]) -> Vec<F> {
        let seven = F::from_base(Fp::from_u64(7));
        let (p0, p1, a0, a1) = (w[0], w[1], w[2], w[3]);
        let (n0, n1, na0, na1) = (w[4], w[5], w[6], w[7]);
        let pa0 = p0 * a0 + seven * (p1 * a1);
        let pa1 = p0 * a1 + p1 * a0;
        alloc::vec![n0 - pa0, n1 - pa1, na0 - a0, na1 - a1]
    }
}

impl AirExt for AlphaPowers {
    fn transition_ext(&self, window: &[Fp2], periodic: &[Fp2]) -> Vec<Fp2> {
        self.transition_impl(window, periodic)
    }
}

impl Air for AlphaPowers {
    fn log_trace_len(&self) -> u32 {
        self.log_len
    }

    fn trace_width(&self) -> usize {
        4
    }

    fn window_size(&self) -> usize {
        2
    }

    fn constraint_degree(&self) -> usize {
        2
    }

    fn num_transition(&self) -> usize {
        4
    }

    fn periodic_columns(&self) -> Vec<Vec<Fp>> {
        Vec::new()
    }

    fn transition(&self, window: &[Fp], periodic: &[Fp]) -> Vec<Fp> {
        self.transition_impl(window, periodic)
    }

    /// alpha^0 is one.
    fn boundary(&self) -> Vec<(usize, usize, Fp)> {
        alloc::vec![(0, 0, Fp::ONE), (1, 0, Fp::ZERO)]
    }
}
