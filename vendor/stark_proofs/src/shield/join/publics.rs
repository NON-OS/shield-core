// NONOS Operating System (AGPL-3.0-or-later)

use crate::crypto::stark::air::RATE;
use crate::crypto::stark::field::Fp;
use alloc::vec::Vec;

/// The frozen intent tuple in the order settleBatch decodes it. Digests occupy
/// four rows each, scalars one, and the recipient four: it is a 160 bit
/// address and a Goldilocks word holds 64, so it is carried the way a digest
/// is, limb 0 the low 64 bits, limb 1 the next 64, limb 2 the top 32 and limb
/// 3 zero. Carrying it as one word bound the low 64 bits of the address and
/// nothing above them, which is a payout an attacker redirects by grinding an
/// address that agrees on those bits.
pub struct Intent {
    pub note_root: [Fp; RATE],
    pub assoc_root: [Fp; RATE],
    pub nf: [[Fp; RATE]; 2],
    pub out_cm: [[Fp; RATE]; 2],
    pub public_amount: u64,
    pub fee: u64,
    pub asset_id: u64,
    pub clearing_price: u64,
    pub recipient: [Fp; RATE],
    /// The fee's payee, carried like `recipient`: four limbs of a 160 bit
    /// address. Zero when the fee is.
    pub fee_recipient: [Fp; RATE],
    /// The earliest time, Unix seconds, the pool may settle this proof. With
    /// the `not_before` build it is word 36 of the statement, pinned and
    /// absorbed like every word, so whoever lands the proof cannot move it.
    /// The wallet publishes at once and the delay still holds. It sits on a
    /// grid of `NOT_BEFORE_GRID_S`, so every proof released into one slot
    /// carries the same value and the draw that chose it is not a fingerprint.
    pub not_before: u64,
    /// The two input notes' limb sums, low then high: the balance region's
    /// running sums after the two input legs, row 2, columns 0 and 4. With the
    /// `claim` build they are words 36 and 37, copy-wired to those cells, and
    /// the inputs' total is `sums[0] + sums[1] * 2^32`. One word cannot carry
    /// the total: no cell holds it, and a copy constraint cannot add two.
    pub input_sums: [u64; 2],
}

pub const NOTE_ROOT: usize = 0;
pub const ASSOC_ROOT: usize = 4;
pub const NF0: usize = 8;
pub const NF1: usize = 12;
pub const OUT_CM0: usize = 16;
pub const OUT_CM1: usize = 20;
pub const PUBLIC_AMOUNT: usize = 24;
pub const FEE: usize = 25;
pub const ASSET_ID: usize = 26;
pub const CLEARING_PRICE: usize = 27;
pub const RECIPIENT: usize = 28;
pub const FEE_RECIPIENT: usize = 32;
pub const NOT_BEFORE: usize = 36;
pub const INPUT_SUM_LO: usize = 36;
pub const INPUT_SUM_HI: usize = 37;
#[cfg(all(feature = "not_before", feature = "claim"))]
compile_error!("`not_before` and `claim` are two statements; build one");
#[cfg(not(any(feature = "not_before", feature = "claim")))]
pub const WORDS: usize = 36;
#[cfg(feature = "not_before")]
pub const WORDS: usize = 37;
#[cfg(feature = "claim")]
pub const WORDS: usize = 38;

/// The grid `not_before` sits on: a multiple of ten minutes.
pub const NOT_BEFORE_GRID_S: u64 = 600;

impl Intent {
    pub fn words(&self) -> Vec<Fp> {
        let mut w = Vec::with_capacity(WORDS);
        w.extend_from_slice(&self.note_root);
        w.extend_from_slice(&self.assoc_root);
        w.extend_from_slice(&self.nf[0]);
        w.extend_from_slice(&self.nf[1]);
        w.extend_from_slice(&self.out_cm[0]);
        w.extend_from_slice(&self.out_cm[1]);
        for v in [
            self.public_amount,
            self.fee,
            self.asset_id,
            self.clearing_price,
        ] {
            w.push(Fp::from_u64(v));
        }
        w.extend_from_slice(&self.recipient);
        w.extend_from_slice(&self.fee_recipient);
        if cfg!(feature = "not_before") {
            w.push(Fp::from_u64(self.not_before));
        }
        if cfg!(feature = "claim") {
            w.push(Fp::from_u64(self.input_sums[0]));
            w.push(Fp::from_u64(self.input_sums[1]));
        }
        w
    }
}
