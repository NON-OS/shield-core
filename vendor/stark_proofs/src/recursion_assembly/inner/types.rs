// NONOS Operating System (AGPL-3.0-or-later)
//! What an inner proof hands the assembly.

use crate::crypto::stark::air::{
    AirExt, ComposeInputs, PeriodicOpeningP, StarkProofExtP, StarkProofExtPPre,
    StarkProofExtPRounds, WiredExt, RATE,
};
use crate::crypto::stark::field::{Fp, Fp2};
use alloc::vec::Vec;

/// The inner proof the assembly verifies, generic over its AIR. The join-split
/// fixture keeps the default `WiredExt`.
pub struct Inner<A: AirExt = WiredExt> {
    pub air: A,
    pub publics: Vec<Fp>,
    pub proof: StarkProofExtP,
    pub ci: ComposeInputs,
    pub t: u64,
    pub g: Fp,
    /// The blowup and the grind the proof was made at: what the outer replays
    /// it against. An outer that is itself an inner carries its own, which is
    /// how one process assembles two layers at two points.
    pub extra: u32,
    pub grind: u32,
    /// The preprocessed sidecar, when the inner proved against a baked
    /// periodic root. The fixture and step inners stay on the plain path and
    /// carry none.
    pub sidecar: Option<Sidecar>,
    /// The second commitment round, when the inner argued its copy constraint
    /// at drawn challenges. A one round inner carries none and the outer
    /// models the shorter transcript.
    pub rounds: Option<Rounds>,
}

impl<A: AirExt> Inner<A> {
    /// The proof as its own verifier reads it, reassembled from the parts the
    /// assembly holds separately. `None` for a one round inner.
    ///
    /// The pieces are split apart here because the recursion consumes them
    /// separately, and a caller that wants to check the inner natively needs
    /// them back in one place rather than rebuilding the shape by hand.
    pub fn rounds_proof(&self) -> Option<StarkProofExtPRounds> {
        let r = self.rounds.as_ref()?;
        let sc = self.sidecar.as_ref()?;
        Some(StarkProofExtPRounds {
            pre: StarkProofExtPPre {
                proof: self.proof.clone(),
                periodic_z: sc.periodic_z.clone(),
                openings: sc.openings.clone(),
            },
            perm_root: r.perm_root,
            region_width: r.region_width,
            perm_paths: r.perm_paths.clone(),
        })
    }
}

/// What a two round inner adds: the permutation columns' own root, where an
/// opened row splits, and one path per query authenticating the second half.
///
/// The outer absorbs `perm_root` at the point the inner drew its challenges
/// and opens the second half of every queried row against it. Without both,
/// the inner's copy constraint is argued at a point the outer never checked
/// was drawn, which is the same hole one layer up.
pub struct Rounds {
    pub perm_root: [Fp; RATE],
    pub region_width: usize,
    pub perm_paths: Vec<Vec<[Fp; RATE]>>,
}

/// What a preprocessed inner adds: the claims, the opened rows, and the root
/// the outer carries as a constant.
pub struct Sidecar {
    pub periodic_z: Vec<Fp2>,
    pub openings: Vec<PeriodicOpeningP>,
    pub root: [Fp; RATE],
}
