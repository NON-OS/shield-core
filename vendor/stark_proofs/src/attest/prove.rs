// NONOS Operating System (AGPL-3.0-or-later)
//! Proving and verifying a slot. A proof leaves only with its zero-knowledge
//! certificate and only after it verifies, in format 7, the bytes a gate and
//! the page read.

use super::circuit::{build, shape, Witness};
use super::native::{hasher, Statement};
use super::{EXTRA_BLOWUP_BITS, RANK_ATTEMPTS};
use crate::crypto::stark::air::{
    domain_params_blown, periodic_root, seed_from_entropy, share_paths, stark_prove_ext_rounds,
    stark_verify_ext_rounds_positions, stark_verify_ext_rounds_shared_why,
};
use crate::crypto::stark::fri::FRI_FOLD_LOG;
use crate::crypto::stark::fri_ext::ATTEST_SHAPE;
use crate::proof_wire::{deserialize_rounds_shared, serialize_rounds, serialize_rounds_shared, ParamSet};
use crate::recursion_assembly::inner::hide_wired;
use crate::zk_rank::check_fri_rank_rounds;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The statement has a kind that is never proven, or the witness is not a depth-8 path.
    Shape,
    /// The slot does not hold the statement's leaf under its root. Nothing was proven.
    Witness,
    /// Fewer than the blinding seed's bytes of entropy.
    Entropy,
    /// The prover produced nothing.
    Prover,
    /// The proof does not verify, or is not at an accepted point.
    NotVerified(String),
    /// Verified, but the zero-knowledge certificate was not reached: prove again.
    Rank(String),
}

/// A point the attestation is proven at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    pub queries: usize,
    pub grind_bits: u32,
}

/// The one point boot and spawn proofs carry: 26 queries, a 28-bit grind.
pub const POINTS: [Point; 1] = [Point {
    queries: ATTEST_SHAPE.1,
    grind_bits: ATTEST_SHAPE.2,
}];

/// The parameter set a proof of `st` at `p` carries in its header.
pub fn params(st: &Statement, p: Point) -> Result<ParamSet, Error> {
    let air = shape(&st.words()).ok_or(Error::Shape)?;
    Ok(ParamSet::of(&air, p.queries, p.grind_bits, EXTRA_BLOWUP_BITS))
}

/// Prove that `w` is a slot of `st`, blinded from `entropy`, at `p`.
pub fn prove(st: &Statement, w: &Witness, entropy: &[u8], p: Point) -> Result<Vec<u8>, Error> {
    prove_both(st, w, entropy, p).map(|(f7, _)| f7)
}

/// `prove`, with the same proof also in the per-query encoding (format 5),
/// which the program-image emitters read. The two encode one proof.
pub fn prove_both(st: &Statement, w: &Witness, entropy: &[u8], p: Point) -> Result<(Vec<u8>, Vec<u8>), Error> {
    if Statement::new(st.root, st.digest, st.kind).is_none() {
        return Err(Error::Shape);
    }
    if !st.holds(&w.siblings, &w.right) {
        return Err(Error::Witness);
    }
    prove_inner(st, w, entropy, p, None)
}

/// The prover with the leaf's lanes written by the caller, for a test that
/// models a forger. Production goes through `prove`.
#[cfg(test)]
pub(super) fn prove_lanes(
    st: &Statement,
    w: &Witness,
    entropy: &[u8],
    p: Point,
    lanes: Option<[crate::crypto::stark::field::Fp; 5]>,
) -> Result<Vec<u8>, Error> {
    prove_inner(st, w, entropy, p, lanes).map(|(f7, _)| f7)
}

fn prove_inner(
    st: &Statement,
    w: &Witness,
    entropy: &[u8],
    p: Point,
    lanes: Option<[crate::crypto::stark::field::Fp; 5]>,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    if !POINTS.contains(&p) {
        return Err(Error::Shape);
    }
    let seed = seed_from_entropy(entropy).ok_or(Error::Entropy)?;
    let words = st.words();
    let b = build(&words, Some(w), lanes).ok_or(Error::Shape)?;
    let params = ParamSet::of(&b.wired, p.queries, p.grind_bits, EXTRA_BLOWUP_BITS);
    let mut witness = b.wired.trace(&b.traces);
    let blind = hide_wired(&hasher(), &b.wired, &mut witness, &seed, p.queries, 1usize << FRI_FOLD_LOG);
    let (rounds, _tree, _air) = stark_prove_ext_rounds(
        b.wired,
        &mut witness,
        p.queries,
        p.grind_bits,
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
        stark_verify_ext_rounds_positions(air, &rounds, p.queries, p.grind_bits, EXTRA_BLOWUP_BITS, &root, &words)
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

/// Verify format 7 bytes against the statement alone, with the circuit and
/// periodic root rebuilt here, never taken from the prover.
pub fn verify(st: &Statement, bytes: &[u8]) -> Result<(), Error> {
    let words = st.words();
    for p in POINTS {
        let air = shape(&words).ok_or(Error::Shape)?;
        let params = ParamSet::of(&air, p.queries, p.grind_bits, EXTRA_BLOWUP_BITS);
        let Some((skeleton, streams)) = deserialize_rounds_shared(bytes, &params) else {
            continue;
        };
        let root = periodic_root(&air, EXTRA_BLOWUP_BITS);
        return stark_verify_ext_rounds_shared_why(
            air,
            &skeleton,
            &streams,
            p.queries,
            p.grind_bits,
            EXTRA_BLOWUP_BITS,
            &root,
            &words,
        )
        .map_err(|why| Error::NotVerified(why.to_string()));
    }
    Err(Error::NotVerified("not a format 7 proof of this circuit at an accepted point".to_string()))
}
