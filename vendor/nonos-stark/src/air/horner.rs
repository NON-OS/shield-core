// NONOS Operating System (AGPL-3.0-or-later)

//! The final polynomial at one query's last point. FRI stops with the
//! polynomial's coefficients in the transcript and each query's last fold
//! must land on its value at that query's point. Pinned as a boundary, that
//! value was the inner proof's, and a verifier baked from one proof's shape
//! accepted only inners with that value: a verifier per proof. Here the
//! coefficients are witness cells the assembly binds to the transcript's
//! absorbs, the point is a witness cell bound to the fold chain's last
//! point, and Horner's rule runs one coefficient a row, highest first, so
//! the value on the last row is the fold's to equal.

use super::super::field::{Felt, Fp, Fp2};
use super::spec::{Air, AirExt};
use alloc::vec::Vec;

/// The extension non-residue: `(p + q X)(r + s X) = (pr + W qs) + (ps + qr) X`.
const W: u64 = 7;

pub struct Horner {
    coeffs: Vec<Fp2>,
    x: Fp2,
}

impl Horner {
    /// `coeffs` lowest degree first, as the transcript absorbed them.
    pub fn new(coeffs: Vec<Fp2>, x: Fp2) -> Horner {
        Horner { coeffs, x }
    }

    /// The coefficient columns: row `j` holds coefficient `n - 1 - j`.
    pub const COEFF: usize = 0;
    /// The point's two lanes, the same on every row.
    pub const X: usize = 2;
    /// The running value; the last coefficient's row plus one holds the result.
    pub const ACC: usize = 4;

    pub fn len(&self) -> usize {
        self.coeffs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.coeffs.is_empty()
    }

    /// The row holding the polynomial's value at the point.
    pub fn value_row(&self) -> usize {
        self.coeffs.len()
    }

    /// The row carrying coefficient `i`.
    pub fn coeff_row(&self, i: usize) -> usize {
        self.coeffs.len() - 1 - i
    }

    pub fn value(&self) -> Fp2 {
        let mut acc = Fp2::ZERO;
        for c in self.coeffs.iter().rev() {
            acc = acc * self.x + *c;
        }
        acc
    }

    pub fn trace(&self) -> Vec<Fp> {
        let rows = 1usize << self.log_trace_len();
        let w = self.trace_width();
        let n = self.coeffs.len();
        let mut tr = alloc::vec![Fp::ZERO; rows * w];
        let mut acc = Fp2::ZERO;
        for r in 0..rows {
            let c = if r < n { self.coeffs[n - 1 - r] } else { Fp2::ZERO };
            tr[r * w + Self::COEFF] = c.c0;
            tr[r * w + Self::COEFF + 1] = c.c1;
            tr[r * w + Self::X] = self.x.c0;
            tr[r * w + Self::X + 1] = self.x.c1;
            tr[r * w + Self::ACC] = acc.c0;
            tr[r * w + Self::ACC + 1] = acc.c1;
            if r < n {
                acc = acc * self.x + c;
            }
        }
        tr
    }

    pub fn transition_gen<F: Felt>(&self, window: &[F], periodic: &[F]) -> Vec<F> {
        self.transition_impl(window, periodic)
    }

    fn transition_impl<F: Felt>(&self, window: &[F], periodic: &[F]) -> Vec<F> {
        let w = self.trace_width();
        let (c0, c1) = (window[Self::COEFF], window[Self::COEFF + 1]);
        let (x0, x1) = (window[Self::X], window[Self::X + 1]);
        let (nx0, nx1) = (window[w + Self::X], window[w + Self::X + 1]);
        let (a0, a1) = (window[Self::ACC], window[Self::ACC + 1]);
        let (na0, na1) = (window[w + Self::ACC], window[w + Self::ACC + 1]);
        let sel = periodic[0];
        let seven = F::from_base(Fp::from_u64(W));
        let ax0 = a0 * x0 + seven * (a1 * x1);
        let ax1 = a0 * x1 + a1 * x0;
        alloc::vec![
            sel * (na0 - (ax0 + c0)),
            sel * (na1 - (ax1 + c1)),
            nx0 - x0,
            nx1 - x1,
        ]
    }
}

impl AirExt for Horner {
    fn transition_ext(&self, window: &[Fp2], periodic: &[Fp2]) -> Vec<Fp2> {
        self.transition_impl(window, periodic)
    }
}

impl Air for Horner {
    fn log_trace_len(&self) -> u32 {
        (self.coeffs.len() + 1).max(2).next_power_of_two().trailing_zeros()
    }

    fn trace_width(&self) -> usize {
        6
    }

    fn window_size(&self) -> usize {
        2
    }

    fn constraint_degree(&self) -> usize {
        3
    }

    fn num_transition(&self) -> usize {
        4
    }

    fn periodic_columns(&self) -> Vec<Vec<Fp>> {
        let rows = 1usize << self.log_trace_len();
        let mut sel = alloc::vec![Fp::ZERO; rows];
        for s in sel.iter_mut().take(self.coeffs.len()) {
            *s = Fp::ONE;
        }
        alloc::vec![sel]
    }

    fn transition(&self, window: &[Fp], periodic: &[Fp]) -> Vec<Fp> {
        self.transition_impl(window, periodic)
    }

    fn boundary(&self) -> Vec<(usize, usize, Fp)> {
        // The value starts at zero; the point's high lane is zero, because a
        // fold point is a base element the fold chain carries in one lane.
        alloc::vec![(Self::ACC, 0, Fp::ZERO), (Self::ACC + 1, 0, Fp::ZERO), (Self::X + 1, 0, Fp::ZERO)]
    }
}
