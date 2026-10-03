// NONOS Operating System (AGPL-3.0-or-later)
//! The statement outside the circuit: the nullifier and the tag as the pool
//! and a claimant compute them, and the eighteen words.

use super::{ACTIVITY_DOMAIN, COUNT, KEY, KEY_DOMAIN, LAMBDA, PAYOUT, SLOTS, TAG, WEEK, WORDS};
use crate::crypto::stark::air::{Poseidon, RATE};
use crate::crypto::stark::field::Fp;
use alloc::vec::Vec;

pub(super) fn hasher() -> Poseidon {
    Poseidon::new(super::LOG_ROUNDS, [Fp::ZERO; RATE])
}

/// A live note's nullifier, `shield::key::nullifier` with `live` true: the
/// leaf the pool records in `NullifierSpent` and D9 folds into Λ_e.
pub fn nullifier(nk: [Fp; RATE], cm: [Fp; RATE], position: u64) -> [Fp; RATE] {
    crate::shield::key::nullifier(&hasher(), nk, cm, position, true)
}

/// The week's tag: one per key per week, unlinkable across weeks without nk.
pub fn tag(nk: [Fp; RATE], week: u64) -> [Fp; RATE] {
    hasher().compress(
        &[Fp::from_u64(ACTIVITY_DOMAIN), nk[0], nk[1], nk[2]],
        &[nk[3], Fp::from_u64(week), Fp::ZERO, Fp::ZERO],
    )
}

/// The key commitment: one per key, the same every week, what a holder
/// registers with the lock it belongs to.
pub fn key_commitment(nk: [Fp; RATE]) -> [Fp; RATE] {
    hasher().compress(
        &[Fp::from_u64(KEY_DOMAIN), nk[0], nk[1], nk[2]],
        &[nk[3], Fp::ZERO, Fp::ZERO, Fp::ZERO],
    )
}

/// What a claim states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Statement {
    pub lambda: [Fp; RATE],
    pub week: u64,
    pub count: u64,
    pub tag: [Fp; RATE],
    pub payout: [Fp; RATE],
    pub key: [Fp; RATE],
}

impl Statement {
    /// `None` for a count outside 1 to 4.
    pub fn new(
        lambda: [Fp; RATE],
        week: u64,
        count: u64,
        tag: [Fp; RATE],
        payout: [Fp; RATE],
        key: [Fp; RATE],
    ) -> Option<Statement> {
        (1..=SLOTS as u64).contains(&count).then_some(Statement {
            lambda,
            week,
            count,
            tag,
            payout,
            key,
        })
    }

    pub fn words(&self) -> Vec<Fp> {
        let mut w = alloc::vec![Fp::ZERO; WORDS];
        w[LAMBDA..LAMBDA + RATE].copy_from_slice(&self.lambda);
        w[WEEK] = Fp::from_u64(self.week);
        w[COUNT] = Fp::from_u64(self.count);
        w[TAG..TAG + RATE].copy_from_slice(&self.tag);
        w[PAYOUT..PAYOUT + RATE].copy_from_slice(&self.payout);
        w[KEY..KEY + RATE].copy_from_slice(&self.key);
        w
    }
}
