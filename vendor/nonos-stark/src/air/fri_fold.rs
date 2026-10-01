// NONOS Operating System (AGPL-3.0-or-later)

//! The FRI fold-consistency gadget: an AIR that checks a query walks the FRI
//! layers correctly. Each row is a layer's opened pair `(a, b) = (f(x), f(-x))`.
//! The transition recomputes the fold
//! `v = (a + b)/2 + beta * (a - b) / (2x)` and checks it equals the value the
//! next layer carries for this query, selected by the position bit. The final
//! layer is pinned to the proof's committed constant. This is the last FRI
//! verification step to become AIR constraints; composed with the Merkle
//! opening gadget and the transcript, it is a recursive FRI verifier.

use super::super::field::{Felt, Fp, Fp2};
use super::spec::{Air, AirExt};
use alloc::vec::Vec;

pub struct FriFold {
    log_layers: u32,
    n_folds: usize,
    /// Inverse of the low domain point at each folding layer.
    x_inv: Vec<Fp>,
    /// The folding challenge at each layer.
    beta: Vec<Fp>,
    /// Whether the folded value lands in the next layer's second slot.
    dir: Vec<bool>,
    /// The committed final-layer value.
    final_value: Fp,
}

impl FriFold {
    pub fn new(
        log_layers: u32,
        n_folds: usize,
        x_inv: Vec<Fp>,
        beta: Vec<Fp>,
        dir: Vec<bool>,
        final_value: Fp,
    ) -> FriFold {
        FriFold { log_layers, n_folds, x_inv, beta, dir, final_value }
    }

    /// The transition over any field, for in-circuit recomputation one layer up.
    ///
    /// Exposed rather than rewritten. A recursion over the settlement outer has
    /// to evaluate this body over the tower, and the only safe way to give it
    /// that is the definition the prover already uses: `transition_ext` and this
    /// both forward to one `transition_impl`, so they cannot drift. A second
    /// copy written over `F` would be a correct computation of a different
    /// constraint, and nothing in the system would report it.
    pub fn transition_gen<F: Felt>(&self, window: &[F], periodic: &[F]) -> Vec<F> {
        self.transition_impl(window, periodic)
    }

    /// The fold-verification constraint over any field: recompute the fold from the
    /// pair `(a, b)` under the layer challenge and require it to land in the next
    /// layer's slot chosen by the direction bit. `inv2` is a base constant embedded.
    fn transition_impl<F: Felt>(&self, window: &[F], periodic: &[F]) -> Vec<F> {
        let (a, b) = (window[0], window[1]);
        let (next_a, next_b) = (window[2], window[3]);
        let sel = periodic[0];
        let x_inv = periodic[1];
        let beta = periodic[2];
        let dir = periodic[3];

        let inv2 = F::from_base(Fp::from_u64(2).inv());
        let even = (a + b) * inv2;
        let odd = (a - b) * inv2 * x_inv;
        let folded = even + beta * odd;

        let expected = (F::ONE - dir) * next_a + dir * next_b;
        alloc::vec![sel * (folded - expected)]
    }
}

impl AirExt for FriFold {
    fn transition_ext(&self, window: &[Fp2], periodic: &[Fp2]) -> Vec<Fp2> {
        self.transition_impl(window, periodic)
    }
}

impl Air for FriFold {
    fn log_trace_len(&self) -> u32 {
        self.log_layers
    }

    fn trace_width(&self) -> usize {
        2
    }

    fn window_size(&self) -> usize {
        2
    }

    fn constraint_degree(&self) -> usize {
        // The fold is linear in the trace, but the constraint multiplies several
        // periodic columns (the selector, the challenge, the inverse point) into
        // it, so the composition degree is that of four interpolated columns. The
        // engine sizes the domain from this.
        4
    }

    fn num_transition(&self) -> usize {
        1
    }

    fn periodic_columns(&self) -> Vec<Vec<Fp>> {
        let n = 1usize << self.log_layers;
        // The fold applies at layers 0..n_folds; other rows are inert.
        let mut sel = Vec::with_capacity(n);
        let mut xi = Vec::with_capacity(n);
        let mut bt = Vec::with_capacity(n);
        let mut dr = Vec::with_capacity(n);
        for r in 0..n {
            let active = r < self.n_folds;
            sel.push(if active { Fp::ONE } else { Fp::ZERO });
            xi.push(if active { self.x_inv[r] } else { Fp::ZERO });
            bt.push(if active { self.beta[r] } else { Fp::ZERO });
            dr.push(if active && self.dir[r] { Fp::ONE } else { Fp::ZERO });
        }
        alloc::vec![sel, xi, bt, dr]
    }

    fn transition(&self, window: &[Fp], periodic: &[Fp]) -> Vec<Fp> {
        self.transition_impl(window, periodic)
    }

    fn boundary(&self) -> Vec<(usize, usize, Fp)> {
        // The layer after the last fold carries the committed final value.
        alloc::vec![(0, self.n_folds, self.final_value)]
    }
}
