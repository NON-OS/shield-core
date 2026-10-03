// NONOS Operating System (AGPL-3.0-or-later)
//! Proving and verifying a weekly activity claim. A proof leaves only after it
//! verifies and with its zero-knowledge certificate, in format 7.

use super::circuit::{build_lanes, shape, Witness};
use super::native::{hasher, key_commitment, nullifier, tag, Statement};
use super::{DEPTH, EXTRA_BLOWUP_BITS, RANK_ATTEMPTS, SLOTS};
use crate::crypto::stark::air::{
    domain_params_blown, periodic_root, seed_from_entropy, share_paths, stark_prove_ext_rounds,
    stark_verify_ext_rounds_positions, stark_verify_ext_rounds_shared_why,
};
use crate::crypto::stark::field::Fp;
use crate::crypto::stark::fri::FRI_FOLD_LOG;
use crate::proof_wire::{
    deserialize_rounds_shared, serialize_rounds, serialize_rounds_shared, ParamSet,
};
use crate::recursion_assembly::inner::hide_wired;
use crate::zk_rank::check_fri_rank_rounds;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A count outside 1 to 4, a path that is not depth 16, or live slots not first.
    Shape,
    /// The claim is false: a nullifier off Λ_e, positions not strictly
    /// increasing, a count other than the live slots, or a tag not this key's
    /// for this week. Nothing was proven.
    Witness(&'static str),
    Entropy,
    Prover,
    NotVerified(String),
    Rank(String),
}

/// Shape A, as payments: a claim is proven on the device that holds the key.
pub const POINT: (usize, u32) = (19, 28);

/// The claim, checked directly before anything is proven.
fn check(st: &Statement, w: &Witness) -> Result<(), Error> {
    let live: Vec<_> = w
        .slots
        .iter()
        .take_while(|s| s.is_some())
        .flatten()
        .collect();
    if w.slots.iter().skip(live.len()).any(Option::is_some) {
        return Err(Error::Shape);
    }
    if live.len() as u64 != st.count {
        return Err(Error::Witness("the count is not the number of live slots"));
    }
    let h = hasher();
    let mut last: Option<u64> = None;
    for s in &live {
        if s.siblings.len() != DEPTH || s.right.len() != DEPTH {
            return Err(Error::Shape);
        }
        let leaf = nullifier(w.nk, s.cm, s.note_position);
        let end = s
            .siblings
            .iter()
            .zip(&s.right)
            .fold(leaf, |node, (sib, &r)| {
                if r {
                    h.compress(sib, &node)
                } else {
                    h.compress(&node, sib)
                }
            });
        if end != st.lambda {
            return Err(Error::Witness(
                "a nullifier is not a leaf of the week's root",
            ));
        }
        let p: u64 = s
            .right
            .iter()
            .enumerate()
            .map(|(k, &r)| (r as u64) << k)
            .sum();
        if last.is_some_and(|q| p <= q) {
            return Err(Error::Witness(
                "the spends are not at strictly increasing positions",
            ));
        }
        last = Some(p);
    }
    if tag(w.nk, st.week) != st.tag {
        return Err(Error::Witness("the tag is not this key's for this week"));
    }
    if key_commitment(w.nk) != st.key {
        return Err(Error::Witness("the key commitment is not this key's"));
    }
    Ok(())
}

/// Prove a claim from fresh entropy.
pub fn prove(st: &Statement, w: &Witness, entropy: &[u8]) -> Result<Vec<u8>, Error> {
    if Statement::new(st.lambda, st.week, st.count, st.tag, st.payout, st.key).is_none()
        || w.slots.len() != SLOTS
    {
        return Err(Error::Shape);
    }
    check(st, w)?;
    prove_inner(st, w, entropy, [Fp::ZERO; SLOTS]).map(|(f7, _)| f7)
}

/// `prove`, with the same proof also in the per-query encoding (format 5),
/// which the program-image emitters read. The two encode one proof.
pub fn prove_both(
    st: &Statement,
    w: &Witness,
    entropy: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    if Statement::new(st.lambda, st.week, st.count, st.tag, st.payout, st.key).is_none()
        || w.slots.len() != SLOTS
    {
        return Err(Error::Shape);
    }
    check(st, w)?;
    prove_inner(st, w, entropy, [Fp::ZERO; SLOTS])
}

/// The parameter set a proof of `st` carries in its header.
pub fn params(st: &Statement) -> Result<ParamSet, Error> {
    let air = shape(&st.words()).ok_or(Error::Shape)?;
    Ok(ParamSet::of(&air, POINT.0, POINT.1, EXTRA_BLOWUP_BITS))
}

/// The prover without the direct check and with each slot's live lane written
/// by the caller, for tests that model a forger. Production goes through `prove`.
#[cfg(test)]
pub(super) fn prove_unchecked(
    st: &Statement,
    w: &Witness,
    entropy: &[u8],
    lane5: [Fp; SLOTS],
) -> Result<Vec<u8>, Error> {
    prove_inner(st, w, entropy, lane5).map(|(f7, _)| f7)
}

fn prove_inner(
    st: &Statement,
    w: &Witness,
    entropy: &[u8],
    lane5: [Fp; SLOTS],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let (q, grind) = POINT;
    let seed = seed_from_entropy(entropy).ok_or(Error::Entropy)?;
    let words = st.words();
    let b = build_lanes(&words, Some(w), lane5).ok_or(Error::Shape)?;
    let params = ParamSet::of(&b.wired, q, grind, EXTRA_BLOWUP_BITS);
    let mut witness = b.wired.trace(&b.traces);
    let blind = hide_wired(
        &hasher(),
        &b.wired,
        &mut witness,
        &seed,
        q,
        1usize << FRI_FOLD_LOG,
    );
    let (rounds, _tree, _air) = stark_prove_ext_rounds(
        b.wired,
        &mut witness,
        q,
        grind,
        EXTRA_BLOWUP_BITS,
        &words,
        None,
        &blind,
    )
    .ok_or(Error::Prover)?;
    drop(witness);

    let air = shape(&words).ok_or(Error::Shape)?;
    let root = periodic_root(&air, EXTRA_BLOWUP_BITS);
    let log_n = domain_params_blown(&air, EXTRA_BLOWUP_BITS).0;
    let positions =
        stark_verify_ext_rounds_positions(air, &rounds, q, grind, EXTRA_BLOWUP_BITS, &root, &words)
            .map_err(|why| Error::NotVerified(why.to_string()))?;
    let cert = check_fri_rank_rounds(
        shape(&words).ok_or(Error::Shape)?,
        &rounds,
        &words,
        EXTRA_BLOWUP_BITS,
        RANK_ATTEMPTS,
    )
    .map_err(Error::Rank)?;
    if !cert.holds {
        return Err(Error::Rank(alloc::format!(
            "{} of {} certified after {} subsets; prove again with fresh entropy",
            cert.mask_rank,
            cert.bound,
            cert.attempts
        )));
    }
    let shared = share_paths(&rounds, &positions, log_n).ok_or(Error::Prover)?;
    let bytes = serialize_rounds_shared(&rounds, &shared, &params);
    verify(st, &bytes)?;
    Ok((bytes, serialize_rounds(&rounds, &params)))
}

/// Verify format 7 bytes against the statement alone, the circuit and
/// periodic root rebuilt here.
pub fn verify(st: &Statement, bytes: &[u8]) -> Result<(), Error> {
    let (q, grind) = POINT;
    let words = st.words();
    let air = shape(&words).ok_or(Error::Shape)?;
    let params = ParamSet::of(&air, q, grind, EXTRA_BLOWUP_BITS);
    let (skeleton, streams) = deserialize_rounds_shared(bytes, &params).ok_or_else(|| {
        Error::NotVerified("not a format 7 proof of this circuit at shape A".to_string())
    })?;
    let root = periodic_root(&air, EXTRA_BLOWUP_BITS);
    stark_verify_ext_rounds_shared_why(
        air,
        &skeleton,
        &streams,
        q,
        grind,
        EXTRA_BLOWUP_BITS,
        &root,
        &words,
    )
    .map_err(|why| Error::NotVerified(why.to_string()))
}
