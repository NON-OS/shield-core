// NONOS Operating System (AGPL-3.0-or-later)

use crate::crypto::stark::air::{NOTE_DOMAIN, NOTE_LIMBS, RATE};
use crate::crypto::stark::field::Fp;

/// The pool hash: 1 << 5 rounds, matching FULL_ROUNDS in PoseidonGoldilocks.sol.
pub const POOL_LOG_ROUNDS: u32 = 5;

#[derive(Clone, Copy)]
pub struct Note {
    pub value: u64,
    pub asset_id: u64,
    pub spend_pk: [u64; 4],
    pub blinding: [u64; 4],
}

impl Note {
    /// Value low then high, asset id, spend key, blinding. The split at 32 bits
    /// is what the range argument bounds.
    pub fn limbs(&self) -> [Fp; NOTE_LIMBS] {
        let mut l = [Fp::ZERO; NOTE_LIMBS];
        l[0] = Fp::from_u64(self.value & 0xFFFF_FFFF);
        l[1] = Fp::from_u64(self.value >> 32);
        l[2] = Fp::from_u64(self.asset_id);
        for i in 0..4 {
            l[3 + i] = Fp::from_u64(self.spend_pk[i]);
            l[7 + i] = Fp::from_u64(self.blinding[i]);
        }
        l
    }
}

/// `[spend_pk, blinding, public]`, the operand order of
/// `cm = compress(public, compress(spend_pk, blinding))`. No quad mixes a public
/// element with a secret one.
pub fn quads(limbs: &[Fp; NOTE_LIMBS]) -> [[Fp; RATE]; 3] {
    let spend_pk = [limbs[3], limbs[4], limbs[5], limbs[6]];
    let blinding = [limbs[7], limbs[8], limbs[9], limbs[10]];
    let public = [limbs[0], limbs[1], limbs[2], Fp::from_u64(NOTE_DOMAIN)];
    [spend_pk, blinding, public]
}
