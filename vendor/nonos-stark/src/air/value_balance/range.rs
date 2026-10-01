// NONOS Operating System (AGPL-3.0-or-later)
//! Range checks by bit decomposition, one segment per value. A segment of
//! `L` rows proves its first cell is in `[0, 2^L)`: each row peels one boolean
//! bit, `acc = 2 acc' + bit`, and the segment's last row holds `acc = bit`.
//! A periodic `end` column marks those last rows, so segments of different
//! lengths share one region. The region ends with a zero row the engine exempts
//! from the transition. The assembly wires each segment's first `acc` to the
//! cell it bounds.

use super::super::super::field::{Felt, Fp, Fp2};
use super::super::spec::{Air, AirExt};
use alloc::vec;
use alloc::vec::Vec;

/// Segments of `bits[k]` rows over `values[k]`, in order.
#[derive(Clone)]
pub struct LimbRange {
    pub bits: Vec<u32>,
    pub values: Vec<u64>,
}

impl LimbRange {
    /// Row where segment `k` starts: the cell the assembly wires to the value.
    pub fn start(&self, k: usize) -> usize {
        self.bits[..k].iter().map(|&b| b as usize).sum()
    }

    fn work_rows(&self) -> usize {
        self.bits.iter().map(|&b| b as usize).sum::<usize>() + 1
    }

    fn ends(&self) -> Vec<Fp> {
        let mut e = vec![Fp::ZERO; self.work_rows()];
        let mut at = 0usize;
        for &b in &self.bits {
            at += b as usize;
            e[at - 1] = Fp::ONE;
        }
        e
    }

    /// `[acc, bit]` per row. A value that does not fit its segment leaves a
    /// nonzero remainder in the last row, which the constraint refuses.
    pub fn trace(&self) -> Vec<Fp> {
        let mut t = vec![Fp::ZERO; self.work_rows() * 2];
        let mut row = 0usize;
        for (&b, &v) in self.bits.iter().zip(&self.values) {
            let mut acc = v as u128;
            for _ in 0..b {
                t[row * 2] = Fp::from_u64(acc as u64);
                t[row * 2 + 1] = Fp::from_u64((acc & 1) as u64);
                acc >>= 1;
                row += 1;
            }
        }
        t
    }

    /// `bit (bit - 1) = 0`, and `acc - 2 acc' - bit` inside a segment or
    /// `acc - bit` on its last row. `window = [acc, bit, acc', bit']`,
    /// `periodic = [end]`.
    pub fn transition_gen<F: Felt>(&self, window: &[F], periodic: &[F]) -> Vec<F> {
        let (acc, bit, next) = (window[0], window[1], window[2]);
        let end = periodic[0];
        let two = F::from_base(Fp::from_u64(2));
        vec![
            bit * (bit - F::ONE),
            (F::ONE - end) * (acc - two * next - bit) + end * (acc - bit),
        ]
    }
}

impl Air for LimbRange {
    fn log_trace_len(&self) -> u32 {
        self.work_rows().next_power_of_two().trailing_zeros()
    }

    fn rows(&self) -> usize {
        self.work_rows()
    }

    fn trace_width(&self) -> usize {
        2
    }

    fn window_size(&self) -> usize {
        2
    }

    fn constraint_degree(&self) -> usize {
        2
    }

    fn num_transition(&self) -> usize {
        2
    }

    fn periodic_columns(&self) -> Vec<Vec<Fp>> {
        vec![self.ends()]
    }

    fn transition(&self, window: &[Fp], periodic: &[Fp]) -> Vec<Fp> {
        self.transition_gen(window, periodic)
    }

    fn boundary(&self) -> Vec<(usize, usize, Fp)> {
        Vec::new()
    }
}

impl AirExt for LimbRange {
    fn transition_ext(&self, window: &[Fp2], periodic: &[Fp2]) -> Vec<Fp2> {
        self.transition_gen(window, periodic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn holds(r: &LimbRange) -> bool {
        let t = r.trace();
        let e = r.ends();
        (0..r.work_rows() - 1).all(|i| {
            let w = [t[i * 2], t[i * 2 + 1], t[i * 2 + 2], t[i * 2 + 3]];
            r.transition(&w, &[e[i]]).iter().all(|c| *c == Fp::ZERO)
        })
    }

    #[test]
    fn values_that_fit_their_segments_satisfy() {
        let r = LimbRange { bits: vec![32, 32, 3], values: vec![0xFFFF_FFFF, 0, 7] };
        assert!(holds(&r));
    }

    #[test]
    fn a_value_one_past_its_segment_is_refused() {
        assert!(!holds(&LimbRange { bits: vec![32], values: vec![1 << 32] }));
        assert!(!holds(&LimbRange { bits: vec![3, 32], values: vec![8, 5] }));
    }

    #[test]
    fn segments_start_where_the_bits_before_them_end() {
        let r = LimbRange { bits: vec![32, 32, 3], values: vec![1, 2, 3] };
        assert_eq!((r.start(0), r.start(1), r.start(2)), (0, 32, 64));
        assert_eq!(Air::rows(&r), 68);
    }
}
