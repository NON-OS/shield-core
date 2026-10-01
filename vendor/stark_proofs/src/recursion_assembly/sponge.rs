// NONOS Operating System (AGPL-3.0-or-later)
//! The duplex schedule both transcript regions replay, recorded as the
//! transcript itself runs it. A `Recorder` drives a `PoseidonTranscript` and
//! writes down the block each absorbed value landed in and the operation
//! each challenge read, so the assembly binds cells it was handed rather
//! than cells it counted: counting is how a wiring ended up four operations
//! past the coefficients once.

use crate::crypto::stark::air::{ood_point_ok, Poseidon, TranscriptOp, RATE};
use crate::crypto::stark::field::{Fp, Fp2};
use crate::crypto::stark::poseidon_transcript::PoseidonTranscript;
use alloc::vec::Vec;

/// A cell of a transcript region: the operation and the lane within it. An
/// absorbed value sits at `(op, lane)` in the inject columns of the block's
/// first row; a squeezed lane sits at `(op, lane)` in the state columns.
pub type OpCell = (usize, usize);

pub struct Recorder {
    ts: PoseidonTranscript,
    ops: Vec<TranscriptOp>,
    block: [Fp; RATE],
    filled: usize,
}

impl Recorder {
    pub fn new(h: &Poseidon) -> Recorder {
        Recorder { ts: PoseidonTranscript::new(h.clone()), ops: Vec::new(), block: [Fp::ZERO; RATE], filled: 0 }
    }

    fn close_block(&mut self) {
        self.ops.push(TranscriptOp::Absorb(self.block));
        self.block = [Fp::ZERO; RATE];
        self.filled = 0;
    }

    fn flush(&mut self) {
        if self.filled > 0 {
            self.close_block();
        }
    }

    /// Absorb one value: the block it landed in and its lane.
    pub fn absorb(&mut self, v: Fp) -> OpCell {
        let cell = (self.ops.len(), self.filled);
        self.block[self.filled] = v;
        self.filled += 1;
        self.ts.absorb(v);
        if self.filled == RATE {
            self.close_block();
        }
        cell
    }

    pub fn absorb_digest(&mut self, d: &[Fp; RATE]) -> [OpCell; RATE] {
        let mut cells = [(0, 0); RATE];
        for (c, v) in cells.iter_mut().zip(d.iter()) {
            *c = self.absorb(*v);
        }
        cells
    }

    fn squeeze_op(&mut self) -> usize {
        self.flush();
        // The squeeze reads the state after a partial block is permuted; the
        // challenge below does that too, so settling first changes nothing
        // it returns and makes the recorded lanes the ones it reads.
        self.ts.settle();
        let op = self.ops.len();
        let st = *self.ts.state();
        self.ops.push(TranscriptOp::Squeeze([st[0], st[1]]));
        op
    }

    /// One base challenge: the operation that read it in lane zero.
    pub fn challenge(&mut self) -> (usize, Fp) {
        let op = self.squeeze_op();
        (op, self.ts.challenge())
    }

    /// One extension challenge: the operation that read it in lanes zero and one.
    pub fn challenge_fp2(&mut self) -> (usize, Fp2) {
        let op = self.squeeze_op();
        (op, self.ts.challenge_fp2())
    }

    /// One index draw: the operation, the element it read, and the index.
    pub fn challenge_index(&mut self, bound: usize) -> (usize, Fp, usize) {
        let (op, c) = self.challenge();
        (op, c, (c.value() as usize) & (bound - 1))
    }

    /// The out-of-domain point, redrawn on the transcript's own rule; the
    /// operation of the draw that stood.
    pub fn ood_point(&mut self, shift: Fp, n: usize, t: usize) -> (usize, Fp2) {
        let (mut op, mut z) = self.challenge_fp2();
        while !ood_point_ok(z, shift, n, t) {
            let next = self.challenge_fp2();
            op = next.0;
            z = next.1;
        }
        (op, z)
    }

    /// The proof of work, checked and bound as the verifier binds it: the
    /// nonce is absorbed into a block of its own, and the next challenge
    /// reads the grinding word.
    pub fn verify_pow(&mut self, nonce: u64, bits: u32) -> bool {
        self.flush();
        if !self.ts.verify_pow(nonce, bits) {
            return false;
        }
        self.block[0] = Fp::from_u64(nonce);
        self.filled = 1;
        true
    }

    /// The schedule, the last partial block closed.
    pub fn finish(mut self) -> Vec<TranscriptOp> {
        assert_eq!(self.filled, self.ts.pending(), "the recorder and the transcript disagree");
        self.flush();
        self.ops
    }
}
