// NONOS Operating System (AGPL-3.0-or-later)
//! The recursion over a real transfer rather than a stand-in: the deployed
//! join-split, depth 32 against the pool tree, its intent absorbed as the
//! transcript publics. Anything the recursion says about one of these, it says
//! about a transfer somebody could actually send.

use super::params::{extra, GRIND, NQ};
use super::prove::{hide, pack, prove, prove_raw, Proved};
use super::types::Inner;
use crate::crypto::stark::air::{
    adopt_rounds_challenges, periodic_root_poseidon, Poseidon, StarkProofExtPRounds,
    WiredMultiGen, RATE,
};
use crate::crypto::stark::field::Fp;
use crate::shield::join::JoinSplit;
use crate::shield::key::Break;
use crate::shield::test::scenario::balanced_deployed;

/// The fixture seed. A wallet draws from entropy; this one is fixed so an
/// artifact built from it reproduces, while the proof keeps the shape a
/// wallet's proof has rather than being the one case where the openings are
/// the trace.
fn seed() -> [Fp; RATE] {
    [
        Fp::from_u64(0x5ded_0001),
        Fp::from_u64(0x5ded_0002),
        Fp::from_u64(0x5ded_0003),
        Fp::from_u64(0x5ded_0004),
    ]
}

/// The deployed transfer at the settlement point, memoized within a process:
/// the witness is deterministic, and a diagnose loop that re-proves it every
/// iteration turns minutes of thinking into half-hours of waiting.
pub fn shield_join_split(h: &Poseidon) -> Inner<WiredMultiGen> {
    let proof = memoized(h);
    // The AIR is rebuilt rather than cached, so it draws the challenges the
    // proof was made against the way a verifier does.
    let js = balanced_deployed(Break::None);
    let publics = js.intent.clone();
    let root = periodic_root_poseidon(&js.wired, extra(), h);
    let mut air = js.wired;
    adopt_rounds_challenges(&mut air, h, &publics, &proof.pre.proof.trace_root);
    pack(
        h,
        Proved {
            air,
            proof,
            publics,
            root,
        },
        extra(),
        GRIND,
    )
}

/// The recursion over a join-split the caller supplies, rather than the
/// deployed fixture. Spending notes that exist in a pool means assembling from
/// those notes, their openings against that pool's published root, and the
/// intent naming where the value goes. Not memoized: there is one of these per
/// spend by definition, and a cache across spends would serve the wrong proof.
pub fn shield_join_split_of(
    h: &Poseidon,
    mut js: JoinSplit,
    seed: Option<&[Fp; RATE]>,
) -> Inner<WiredMultiGen> {
    let blind = match seed {
        Some(s) => hide(h, &mut js, s, NQ),
        None => alloc::vec::Vec::new(),
    };
    prove(h, js, NQ, GRIND, extra(), &blind)
}

/// The deployed transfer proved hiding, with a fresh per-proof seed drawn from
/// the capsule's CSPRNG. This is the entry the private-transfer cutover calls.
pub fn shield_join_split_hidden(h: &Poseidon, seed: &[Fp; RATE]) -> Inner<WiredMultiGen> {
    let mut js = balanced_deployed(Break::None);
    let blind = hide(h, &mut js, seed, NQ);
    prove(h, js, NQ, GRIND, extra(), &blind)
}

/// The deployed transfer at an explicit soundness point, unmemoized, so the
/// cost of a transaction and the cost of a settlement are two measured numbers
/// rather than one standing in for both.
pub fn shield_join_split_at(
    h: &Poseidon,
    nq: usize,
    grind: u32,
    extra_bits: u32,
) -> Inner<WiredMultiGen> {
    prove(h, balanced_deployed(Break::None), nq, grind, extra_bits, &[])
}

#[cfg(feature = "std")]
fn memoized(h: &Poseidon) -> StarkProofExtPRounds {
    static PROOF: std::sync::OnceLock<StarkProofExtPRounds> = std::sync::OnceLock::new();
    PROOF.get_or_init(|| deployed_proof(h)).clone()
}

/// Without std there is no process-wide cell to keep it in: proved per call.
#[cfg(not(feature = "std"))]
fn memoized(h: &Poseidon) -> StarkProofExtPRounds {
    deployed_proof(h)
}

fn deployed_proof(h: &Poseidon) -> StarkProofExtPRounds {
    let mut js = balanced_deployed(Break::None);
    let blind = hide(h, &mut js, &seed(), NQ);
    prove_raw(h, js, NQ, GRIND, extra(), &blind).proof
}
