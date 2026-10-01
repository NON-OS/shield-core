// NONOS Operating System (AGPL-3.0-or-later)

//! Post-quantum capsule attestation: a context-bound STARK proof that the
//! prover knows an enrolled secret. The leaf stays private, the path is public,
//! as the Curve25519 gate hides its secret and reveals its siblings.

use super::super::super::field::Fp;
use super::super::wire::deserialize::deserialize_proof;
use super::super::poseidon::{Poseidon, RATE};
use super::super::verify::stark_verify_bound;
use super::super::MerkleMembership;

/// Verify a context-bound membership attestation. `root` is the kernel's own
/// trusted policy root, never the prover's; `context` binds the proof to the
/// capsule. True only for a valid proof under exactly this root and context.
#[must_use = "an attestation result must gate the spawn"]
#[allow(clippy::too_many_arguments)]
pub fn verify_membership_attestation(
    hasher: &Poseidon,
    log_rounds: u32,
    root: [Fp; RATE],
    siblings: &[[Fp; RATE]],
    directions: &[bool],
    n_queries: usize,
    proof_bytes: &[u8],
    context: &[u8],
) -> bool {
    if siblings.is_empty() || siblings.len() != directions.len() {
        return false;
    }
    let Some(proof) = deserialize_proof(proof_bytes) else {
        return false;
    };
    let air = MerkleMembership::new(
        hasher.clone(),
        log_rounds,
        root,
        siblings.to_vec(),
        directions.to_vec(),
    );
    stark_verify_bound(&air, &proof, n_queries, context)
}
