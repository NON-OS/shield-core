// NONOS Operating System (AGPL-3.0-or-later)

//! A Fiat-Shamir transcript over the Poseidon permutation, the algebraic
//! counterpart of the keccak transcript. A duplex at the sponge's rate:
//! absorbed values fill the first four lanes one at a time and the state
//! permutes when the block is full; a challenge permutes any partial block
//! first, reads the first lane, an extension challenge the first two, and
//! permutes again. `TranscriptCheck` proves exactly this schedule, so a
//! proof made with this transcript has its challenges re-derived inside a
//! STARK: the requirement for recursion. One value a permutation was what
//! it did before, and the outer's frame alone was 2,576 permutations.

use super::air::{Poseidon, RATE, WIDTH};
use super::field::{Fp, Fp2};
use alloc::vec::Vec;

pub struct PoseidonTranscript {
    hasher: Poseidon,
    state: [Fp; WIDTH],
    /// Lanes of the current block already holding a value, under `RATE`.
    pending: usize,
}

impl PoseidonTranscript {
    pub fn new(hasher: Poseidon) -> PoseidonTranscript {
        PoseidonTranscript { hasher, state: [Fp::ZERO; WIDTH], pending: 0 }
    }

    /// The sponge state, for a recorder that mirrors this schedule.
    pub fn state(&self) -> &[Fp; WIDTH] {
        &self.state
    }

    /// Values of the current block not yet permuted.
    pub fn pending(&self) -> usize {
        self.pending
    }

    fn permute_block(&mut self) {
        self.state = self.hasher.permute(self.state);
        self.pending = 0;
    }

    /// Permute a pending partial block now, as the next challenge would. A
    /// recorder that reads `state` before a squeeze calls this first, or it
    /// records the state before the block's permutation and the squeeze it
    /// writes down is not the one the challenge reads.
    pub fn settle(&mut self) {
        self.flush();
    }

    /// A partial block is permuted before anything is read from the state.
    fn flush(&mut self) {
        if self.pending > 0 {
            self.permute_block();
        }
    }

    /// Absorb one field element into the next lane of the block; a full
    /// block permutes.
    pub fn absorb(&mut self, value: Fp) {
        self.state[self.pending] = self.state[self.pending] + value;
        self.pending += 1;
        if self.pending == RATE {
            self.permute_block();
        }
    }

    /// Absorb a rate-sized digest, lane by lane.
    pub fn absorb_digest(&mut self, digest: &[Fp; RATE]) {
        for v in digest.iter() {
            self.absorb(*v);
        }
    }

    /// Draw a field-element challenge: the first lane, then a permutation.
    pub fn challenge(&mut self) -> Fp {
        self.flush();
        let c = self.state[0];
        self.permute_block();
        c
    }

    /// Draw a query index in `[0, bound)`. `bound` is a power of two, so masking
    /// is unbiased.
    pub fn challenge_index(&mut self, bound: usize) -> usize {
        (self.challenge().value() as usize) & (bound - 1)
    }

    /// Draw a challenge from the degree-2 extension: the first two lanes, then
    /// one permutation. Money-grade fold and DEEP challenges are drawn here,
    /// not from the base field: the low-degree test's soundness error is
    /// `degree / |challenge field|`, so `Fp2` (~2^128) reaches `2^-128` where
    /// the base field caps near `2^-64`.
    pub fn challenge_fp2(&mut self) -> Fp2 {
        self.flush();
        let c = Fp2::new(self.state[0], self.state[1]);
        self.permute_block();
        c
    }

    /// A vector of `n` batching coefficients from one squeeze: alpha, then
    /// alpha^0 through alpha^(n-1). A coefficient per term cost the wrap one
    /// permutation per lane, thousands for the outer; powers of one
    /// challenge cost one permutation and a four column region. The batched
    /// polynomial is nonzero of degree below `n` in alpha, so a random alpha
    /// misses its roots except with probability under `n` over 2^128.
    pub fn challenge_powers(&mut self, n: usize) -> Vec<Fp2> {
        let alpha = self.challenge_fp2();
        let mut v = Vec::with_capacity(n);
        let mut p = Fp2::ONE;
        for _ in 0..n {
            v.push(p);
            p = p * alpha;
        }
        v
    }

    /// The grinding word for a nonce against the flushed state: the first
    /// lane of the permutation with the nonce in lane zero. It is the same
    /// permutation the nonce's own block runs when the next challenge flushes
    /// it, so the first challenge after the grind reads this very word; a
    /// verifier in a circuit checks the grind on that cell.
    fn pow_word(&self, nonce: u64) -> u64 {
        let mut s = self.state;
        s[0] = s[0] + Fp::from_u64(nonce);
        self.hasher.permute(s)[0].value()
    }

    /// Prover-side grinding: find a nonce whose grinding word has at least `bits`
    /// leading zero bits, then bind it, adding `bits` of proof-of-work.
    pub fn grind(&mut self, bits: u32) -> u64 {
        self.flush();
        let nonce = self.grind_search(bits);
        self.absorb(Fp::from_u64(nonce));
        nonce
    }

    /// The proof-of-work search: the smallest nonce meeting the work. The
    /// keccak transcript has searched in parallel blocks since the grind
    /// became the dominant cost of an emit; this one did not, so every bit of
    /// the inner's soundness was bought on one core of however many the box
    /// has. The parallel form searches a block across every core and takes
    /// the lowest hit in it, so it returns the identical nonce the serial
    /// loop would: bit-exact, and the proof does not move.
    #[cfg(not(feature = "parallel"))]
    fn grind_search(&self, bits: u32) -> u64 {
        let mut nonce = 0u64;
        while self.pow_word(nonce).leading_zeros() < bits {
            nonce = nonce.wrapping_add(1);
        }
        nonce
    }

    #[cfg(feature = "parallel")]
    fn grind_search(&self, bits: u32) -> u64 {
        use rayon::prelude::*;
        const BLOCK: u64 = 1 << 24;
        let mut base = 0u64;
        loop {
            let hit = (base..base + BLOCK)
                .into_par_iter()
                .find_first(|&n| self.pow_word(n).leading_zeros() >= bits);
            if let Some(n) = hit {
                return n;
            }
            base += BLOCK;
        }
    }

    /// Verifier-side grinding check: accept only if the nonce meets the proof-of-
    /// work, and bind it exactly as the prover did so both draw the same challenges.
    pub fn verify_pow(&mut self, nonce: u64, bits: u32) -> bool {
        self.flush();
        if self.pow_word(nonce).leading_zeros() < bits {
            return false;
        }
        self.absorb(Fp::from_u64(nonce));
        true
    }
}
