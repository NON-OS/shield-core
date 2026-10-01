// NONOS Operating System (AGPL-3.0-or-later)

//! A drawn query index, bound to the squeeze that drew it. The transcript
//! squeezes a field element; the verifier keeps its low `log n` bits as the
//! index and derives the evaluation point `shift * omega^index` from them.
//! Left to the witness, the bits would be the prover's choice and every
//! opening and fold would be checked at positions it picked, which is no
//! low-degree test at all. This region decomposes the squeezed element into
//! its 64 bits, low bit first, recovers the element from them so the
//! assembly can bind it to the squeeze cell, and walks the point product
//! chain over the low bits so the same bits that open the paths give the
//! point. The decomposition is canonical: a value at or above the modulus
//! has its high 32 bits all one and a nonzero low half, and one lane
//! refuses exactly that, so a prover cannot offer the bits of `v + p` for
//! `v`. The grind is the same cell: the first index drawn after the nonce
//! reads the grinding word, so its top bits are pinned to zero on that
//! instance and the proof of work is checked where it happened.

use super::super::field::{Felt, Fp, Fp2};
use super::spec::{Air, AirExt};
use alloc::vec::Vec;

/// Bits of a squeezed element.
pub const BITS: usize = 64;
/// Half of them: the modulus is `2^64 - 2^32 + 1`.
const HALF: usize = 32;

pub struct IndexDraw {
    consts: Vec<Fp>,
    shift: Fp,
    value: u64,
    zero_top: usize,
}

impl IndexDraw {
    /// The chain over the squeezed `value`: the point walks `point_bits` low
    /// bits, `zero_top` high bits are pinned to zero (the grind).
    pub fn new(omega: Fp, shift: Fp, point_bits: usize, value: u64, zero_top: usize) -> IndexDraw {
        assert!(point_bits <= BITS && zero_top <= BITS, "a draw is 64 bits");
        let consts: Vec<Fp> = (0..point_bits).map(|k| omega.pow(1u64 << k)).collect();
        IndexDraw { consts, shift, value, zero_top }
    }

    /// The bit column, row `k` holding bit `k`.
    pub const BIT: usize = 0;
    /// The running point's two lanes.
    pub const POINT: usize = 1;
    /// The running value: the bits taken at their weights.
    pub const VALUE: usize = 3;
    const LOW: usize = 4;
    const HIGH_PRODUCT: usize = 5;

    /// The row carrying the recovered value and the finished point.
    pub fn value_row(&self) -> usize {
        BITS
    }

    /// The point the low bits give.
    pub fn point(&self) -> Fp2 {
        let mut x = Fp2::from_base(self.shift);
        for (k, c) in self.consts.iter().enumerate() {
            if (self.value >> k) & 1 == 1 {
                x = x * Fp2::from_base(*c);
            }
        }
        x
    }

    pub fn trace(&self) -> Vec<Fp> {
        let rows = 1usize << self.log_trace_len();
        let w = self.trace_width();
        let mut tr = alloc::vec![Fp::ZERO; rows * w];
        let mut x = Fp2::from_base(self.shift);
        let mut acc = 0u64;
        let mut low = 0u64;
        let mut hp = Fp::ONE;
        for r in 0..rows {
            let b = if r < BITS { (self.value >> r) & 1 } else { 0 };
            tr[r * w + Self::BIT] = Fp::from_u64(b);
            tr[r * w + Self::POINT] = x.c0;
            tr[r * w + Self::POINT + 1] = x.c1;
            tr[r * w + Self::VALUE] = Fp::from_u64(acc);
            tr[r * w + Self::LOW] = Fp::from_u64(low);
            tr[r * w + Self::HIGH_PRODUCT] = hp;
            if r < BITS {
                acc |= b << r;
                if r < HALF {
                    low |= b << r;
                } else {
                    hp = hp * Fp::from_u64(b);
                }
            }
            if b == 1 && r < self.consts.len() {
                x = x * Fp2::from_base(self.consts[r]);
            }
        }
        tr
    }

    pub fn transition_gen<F: Felt>(&self, window: &[F], periodic: &[F]) -> Vec<F> {
        self.transition_impl(window, periodic)
    }

    fn transition_impl<F: Felt>(&self, window: &[F], periodic: &[F]) -> Vec<F> {
        let w = self.trace_width();
        let one = F::ONE;
        let b = window[Self::BIT];
        let (x0, x1) = (window[Self::POINT], window[Self::POINT + 1]);
        let (nx0, nx1) = (window[w + Self::POINT], window[w + Self::POINT + 1]);
        let (acc, nacc) = (window[Self::VALUE], window[w + Self::VALUE]);
        let (lo, nlo) = (window[Self::LOW], window[w + Self::LOW]);
        let (hp, nhp) = (window[Self::HIGH_PRODUCT], window[w + Self::HIGH_PRODUCT]);
        let (c, pow, lowsel, hisel, endsel) =
            (periodic[0], periodic[1], periodic[2], periodic[3], periodic[4]);
        // scalar = 1 + b (c - 1): the constant when the bit is set, one otherwise;
        // past the point bits c is one and the point carries.
        let scalar = one + b * (c - one);
        alloc::vec![
            b * (one - b),
            nx0 - x0 * scalar,
            nx1 - x1 * scalar,
            nacc - (acc + b * pow),
            nlo - (lo + b * pow * lowsel),
            nhp - hp * (one - hisel + hisel * b),
            // A value at or above the modulus: every high bit set and a nonzero
            // low half. Refused on the row the decomposition ends.
            endsel * hp * lo,
        ]
    }
}

impl AirExt for IndexDraw {
    fn transition_ext(&self, window: &[Fp2], periodic: &[Fp2]) -> Vec<Fp2> {
        self.transition_impl(window, periodic)
    }
}

impl Air for IndexDraw {
    fn log_trace_len(&self) -> u32 {
        (BITS + 1).next_power_of_two().trailing_zeros()
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
        7
    }

    fn periodic_columns(&self) -> Vec<Vec<Fp>> {
        let rows = 1usize << self.log_trace_len();
        let mut c = alloc::vec![Fp::ONE; rows];
        let mut pow = alloc::vec![Fp::ZERO; rows];
        let mut lowsel = alloc::vec![Fp::ZERO; rows];
        let mut hisel = alloc::vec![Fp::ZERO; rows];
        let mut endsel = alloc::vec![Fp::ZERO; rows];
        for r in 0..BITS {
            if r < self.consts.len() {
                c[r] = self.consts[r];
            }
            pow[r] = Fp::from_u64(1u64 << r);
            if r < HALF {
                lowsel[r] = Fp::ONE;
            } else {
                hisel[r] = Fp::ONE;
            }
        }
        endsel[BITS] = Fp::ONE;
        alloc::vec![c, pow, lowsel, hisel, endsel]
    }

    fn transition(&self, window: &[Fp], periodic: &[Fp]) -> Vec<Fp> {
        self.transition_impl(window, periodic)
    }

    fn boundary(&self) -> Vec<(usize, usize, Fp)> {
        // The point starts at shift, the sums empty, the high product at one;
        // the value and the point are witness, bound by the assembly. The
        // grind pins the top bits of the one draw that read the grinding word.
        let mut b = alloc::vec![
            (Self::POINT, 0, self.shift),
            (Self::POINT + 1, 0, Fp::ZERO),
            (Self::VALUE, 0, Fp::ZERO),
            (Self::LOW, 0, Fp::ZERO),
            (Self::HIGH_PRODUCT, 0, Fp::ONE),
        ];
        for k in BITS - self.zero_top..BITS {
            b.push((Self::BIT, k, Fp::ZERO));
        }
        b
    }
}
