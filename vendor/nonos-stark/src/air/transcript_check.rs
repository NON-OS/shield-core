// NONOS Operating System (AGPL-3.0-or-later)

//! The transcript-derivation gadget: proving a proof's Fiat-Shamir challenges
//! were honestly squeezed from its committed data, so the challenges are
//! proven, not trusted. It runs the exact duplex of `PoseidonTranscript`: an
//! absorb block adds up to `RATE` values into the first lanes and permutes, a
//! squeeze reads the first lanes and permutes. Each operation is one
//! permutation, arithmetized round by round with the S-box over witnessed
//! squares, so a round is degree three. In the per-proof form the absorbed
//! values ride periodic columns and the squeezes are pinned; in the witness
//! form the absorbed values ride four trace columns under a structural
//! selector and nothing is pinned, the assembly's grand product binding every
//! absorbed value to its source and every squeeze to its consumer.

use super::super::field::{Felt, Fp};
use super::poseidon::{Poseidon, RATE, WIDTH};
use super::spec::{Air, AirExt};
use alloc::vec::Vec;

/// One transcript operation: a block of absorbed values, zero where the
/// block was partial, or a squeeze carrying the two lanes it read.
pub enum TranscriptOp {
    Absorb([Fp; RATE]),
    Squeeze([Fp; 2]),
}

/// The first absorb column of the witness form; lane `j` of a block sits at
/// `INJECT + j` on the block's first row.
pub const INJECT: usize = WIDTH;

pub struct TranscriptCheck {
    hasher: Poseidon,
    log_rounds: u32,
    ops: Vec<TranscriptOp>,
    witness_inject: bool,
}

impl TranscriptCheck {
    /// The per-proof form: absorbed values on periodic columns, squeezes
    /// pinned as boundaries. Instance-specific, fine for a per-proof AIR.
    pub fn new(hasher: Poseidon, log_rounds: u32, ops: Vec<TranscriptOp>) -> TranscriptCheck {
        TranscriptCheck { hasher, log_rounds, ops, witness_inject: false }
    }

    /// The production form: the absorbed values ride four trace columns gated
    /// by a structural selector and the squeezes are not pinned. The AIR is
    /// then instance-independent: round constants and the selector are the
    /// only periodic columns, the sponge-empty rows the only boundaries.
    pub fn new_witness(
        hasher: Poseidon,
        log_rounds: u32,
        ops: Vec<TranscriptOp>,
    ) -> TranscriptCheck {
        TranscriptCheck { hasher, log_rounds, ops, witness_inject: true }
    }

    fn rounds(&self) -> usize {
        1usize << self.log_rounds
    }

    /// The block absorbed on `row`'s operation, all zero off an absorb start.
    fn inject_at(&self, row: usize) -> [Fp; RATE] {
        let l = self.rounds();
        if row.is_multiple_of(l) && row / l < self.ops.len() {
            if let TranscriptOp::Absorb(v) = self.ops[row / l] {
                return v;
            }
        }
        [Fp::ZERO; RATE]
    }

    /// The structural inject selector: one at every absorb-operation start, zero
    /// elsewhere. Instance-independent: it depends only on the op schedule.
    fn inject_sel(&self, row: usize) -> Fp {
        let l = self.rounds();
        if row.is_multiple_of(l) && row / l < self.ops.len() {
            if let TranscriptOp::Absorb(_) = self.ops[row / l] {
                return Fp::ONE;
            }
        }
        Fp::ZERO
    }

    /// Where the witnessed squares start.
    fn squares_at(&self) -> usize {
        if self.witness_inject {
            WIDTH + RATE
        } else {
            WIDTH
        }
    }

    /// The witness: the sponge state at every round, the absorbed block added
    /// into the first lanes at each operation start, the squares of the
    /// injected state beside it. Padding rows keep permuting.
    pub fn trace(&self) -> Vec<Fp> {
        let n = 1usize << self.log_trace_len();
        let l = self.rounds();
        let w = self.trace_width();
        let sq = self.squares_at();
        let mut state = [Fp::ZERO; WIDTH];
        let mut tr = alloc::vec![Fp::ZERO; n * w];
        for row in 0..n {
            tr[row * w..row * w + WIDTH].copy_from_slice(&state);
            let inj = self.inject_at(row);
            let mut injected = state;
            for j in 0..RATE {
                injected[j] = injected[j] + inj[j];
                if self.witness_inject {
                    tr[row * w + INJECT + j] = inj[j];
                }
            }
            for j in 0..WIDTH {
                let x2 = injected[j] * injected[j];
                tr[row * w + sq + j] = x2;
                tr[row * w + sq + WIDTH + j] = x2 * x2;
            }
            state = self.hasher.round_with_rc(&injected, &self.hasher.round_constant(row % l));
        }
        tr
    }

    /// The transition over any field, for in-circuit recomputation one layer up.
    /// Forwards to the definition the prover uses, so the two cannot drift.
    pub fn transition_gen<F: Felt>(&self, window: &[F], periodic: &[F]) -> Vec<F> {
        self.transition_impl(window, periodic)
    }

    fn transition_impl<F: Felt>(&self, window: &[F], periodic: &[F]) -> Vec<F> {
        let w = self.trace_width();
        let sq = self.squares_at();
        let mut state = [F::ZERO; WIDTH];
        state.copy_from_slice(&window[..WIDTH]);
        let mut rc = [F::ZERO; WIDTH];
        rc.copy_from_slice(&periodic[..WIDTH]);
        // The absorbed block enters additively, so the sponge keeps the S-box's
        // degree: witnessed columns in the production form, periodic in the
        // per-proof one, never multiplied by the selector.
        for j in 0..RATE {
            let v = if self.witness_inject { window[INJECT + j] } else { periodic[WIDTH + j] };
            state[j] = state[j] + v;
        }
        let mut x2 = [F::ZERO; WIDTH];
        let mut x4 = [F::ZERO; WIDTH];
        x2.copy_from_slice(&window[sq..sq + WIDTH]);
        x4.copy_from_slice(&window[sq + WIDTH..sq + 2 * WIDTH]);
        let (pr, c2, c4) = self.hasher.round_split_generic(&state, &x2, &x4, &rc);
        let mut out = Vec::with_capacity(3 * WIDTH + RATE);
        for (j, next) in window[w..w + WIDTH].iter().enumerate() {
            out.push(*next - pr[j]);
        }
        out.extend(c2);
        out.extend(c4);
        // A witnessed block must be zero except at an absorb start, so it cannot
        // inject off schedule: the selector masks every lane on other rows.
        if self.witness_inject {
            let sel = periodic[WIDTH];
            for j in 0..RATE {
                out.push((F::ONE - sel) * window[INJECT + j]);
            }
        }
        out
    }
}

impl AirExt for TranscriptCheck {
    fn transition_ext(
        &self,
        window: &[super::super::field::Fp2],
        periodic: &[super::super::field::Fp2],
    ) -> Vec<super::super::field::Fp2> {
        self.transition_impl(window, periodic)
    }
}

impl Air for TranscriptCheck {
    fn log_trace_len(&self) -> u32 {
        (self.ops.len() * self.rounds()).next_power_of_two().trailing_zeros()
    }

    fn trace_width(&self) -> usize {
        self.squares_at() + 2 * WIDTH
    }

    fn window_size(&self) -> usize {
        2
    }

    fn constraint_degree(&self) -> usize {
        3
    }

    fn num_transition(&self) -> usize {
        if self.witness_inject {
            3 * WIDTH + RATE
        } else {
            3 * WIDTH
        }
    }

    fn periodic_columns(&self) -> Vec<Vec<Fp>> {
        let n = 1usize << self.log_trace_len();
        let l = self.rounds();
        // The round constants, then the selector (witness form) or the
        // absorbed block (per-proof form).
        let extra = if self.witness_inject { 1 } else { RATE };
        let mut cols: Vec<Vec<Fp>> = (0..WIDTH + extra).map(|_| alloc::vec![Fp::ZERO; n]).collect();
        for row in 0..n {
            let rc = self.hasher.round_constant(row % l);
            for (j, col) in cols.iter_mut().take(WIDTH).enumerate() {
                col[row] = rc[j];
            }
            if self.witness_inject {
                cols[WIDTH][row] = self.inject_sel(row);
            } else {
                let inj = self.inject_at(row);
                for j in 0..RATE {
                    cols[WIDTH + j][row] = inj[j];
                }
            }
        }
        cols
    }

    fn transition(&self, window: &[Fp], periodic: &[Fp]) -> Vec<Fp> {
        self.transition_impl(window, periodic)
    }

    fn boundary(&self) -> Vec<(usize, usize, Fp)> {
        let mut b = Vec::new();
        // The sponge starts empty.
        for j in 0..WIDTH {
            b.push((j, 0, Fp::ZERO));
        }
        // In the per-proof form each squeeze pins the two lanes it read. In the
        // production form they are witness cells at the squeeze row, bound by
        // the assembly's grand product to their consumers, so nothing is pinned.
        if !self.witness_inject {
            let l = self.rounds();
            for (oi, op) in self.ops.iter().enumerate() {
                if let TranscriptOp::Squeeze(c) = op {
                    b.push((0, oi * l, c[0]));
                    b.push((1, oi * l, c[1]));
                }
            }
        }
        b
    }
}
