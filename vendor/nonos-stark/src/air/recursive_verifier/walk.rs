// NONOS Operating System (AGPL-3.0-or-later)

//! The recursive verifier composed from the checked components: the per-query
//! openings at one FRI layer, their membership region, and the walk that runs
//! both over every query.

use super::super::super::field::Fp;
use super::super::poseidon::{Poseidon, RATE};
use super::super::super::fri::root_of_unity;
use super::super::super::fri_poseidon::FriProof;
use super::super::multi_membership::{MultiMembership, Opening};
use super::super::wire::types::StarkProof;
use super::super::verify::stark_verify;
use super::{FinalLayerConstant, FriTranscript};
use alloc::vec::Vec;

/// The direction bits of a leaf position, one per tree level from the leaf up:
/// bit `k` is the position's `k`-th bit, which is the child side at level `k`.
fn directions(index: usize, depth: usize) -> Vec<bool> {
    (0..depth).map(|k| (index >> k) & 1 == 1).collect()
}

/// The rate-sized leaf a codeword value commits to: the value in lane zero, the
/// rest zero, matching the FRI commitment.
fn value_leaf(v: Fp) -> [Fp; RATE] {
    let mut leaf = [Fp::ZERO; RATE];
    leaf[0] = v;
    leaf
}

/// The two openings a query induces at one FRI layer: the value at the queried
/// half-position and its fold partner, each with its committed path.
pub fn layer_openings(
    proof: &FriProof,
    query: usize,
    layer: usize,
    index: usize,
    log_n: u32,
) -> Vec<Opening> {
    let half = (1usize << log_n) >> (layer + 1);
    let i = index % half;
    let op = &proof.queries[query].layers[layer];
    let root = proof.roots[layer];
    vec![
        Opening {
            leaf: value_leaf(op.a),
            root,
            siblings: op.a_path.clone(),
            directions: directions(i, op.a_path.len()),
        },
        Opening {
            leaf: value_leaf(op.b),
            root,
            siblings: op.b_path.clone(),
            directions: directions(i + half, op.b_path.len()),
        },
    ]
}

/// The membership AIR a query's layer openings must satisfy, rebuilt from the
/// proof so a verifier and a prover agree on it without trust.
pub fn layer_membership(
    proof: &FriProof,
    hasher: &Poseidon,
    log_rounds: u32,
    query: usize,
    layer: usize,
    index: usize,
    log_n: u32,
) -> MultiMembership {
    MultiMembership::new(
        hasher.clone(),
        log_rounds,
        layer_openings(proof, query, layer, index, log_n),
    )
}

/// Verify a recursion-ready FRI proof from the checked components. The fold
/// challenges are re-derived by the transcript AIR rather than trusted; the
/// Merkle openings at every query and layer are proven committed by the
/// membership AIR; the folds are the cheap public linear check, using the
/// re-derived challenges; and the final layer is a single constant the folds
/// land on. Every expensive step is a STARK, so a verifier of this verifier is
/// itself a STARK: recursion. The component proofs are supplied by the prover;
/// `transcript_proof` attests the challenges, and `membership_proofs` is one
/// proof per `(query, layer)` in row-major order.
#[allow(clippy::too_many_arguments)]
pub fn recursive_verify(
    proof: &FriProof,
    hasher: &Poseidon,
    log_rounds: u32,
    shift: Fp,
    log_n: u32,
    log_blowup: u32,
    n_queries: usize,
    stark_queries: usize,
    transcript_proof: &StarkProof,
    membership_proofs: &[StarkProof],
) -> bool {
    let n = 1usize << log_n;
    let blowup = 1usize << log_blowup;
    let n_folds = (log_n - log_blowup) as usize;

    // Structural: the proof and the supplied component proofs are the right
    // shape for these parameters.
    if proof.roots.len() != n_folds
        || proof.final_layer.len() != blowup
        || proof.queries.len() != n_queries
        || membership_proofs.len() != n_queries * n_folds
    {
        return false;
    }

    // 1. The fold and query challenges, re-derived and proven from the roots and
    // the final layer.
    let transcript = FriTranscript::new(
        hasher.clone(),
        log_rounds,
        proof.roots.clone(),
        proof.final_layer.to_vec(),
        n_queries,
    );
    if !stark_verify(&transcript, transcript_proof, stark_queries) {
        return false;
    }
    let betas = transcript.betas();
    let query_challenges = transcript.query_challenges();

    // 2. The low-degree conclusion: the final layer is a single constant.
    let final_value = proof.final_layer[0];
    for v in &proof.final_layer {
        if *v != final_value {
            return false;
        }
    }

    // 3. Each query: the openings proven committed, then the public folds land
    // on the next layer, ending on the final constant.
    let base_omega = root_of_unity(log_n);
    let inv2 = Fp::from_u64(2).inv();
    for (q, qp) in proof.queries.iter().enumerate() {
        if qp.layers.len() != n_folds {
            return false;
        }
        // The masked query position: the transcript challenge into the domain.
        let index = (query_challenges[q].value() as usize) & (n - 1);

        for m in 0..n_folds {
            // The openings at this layer are proven committed by the membership
            // AIR, rebuilt from the proof so no opened value is trusted.
            let air = layer_membership(proof, hasher, log_rounds, q, m, index, log_n);
            if !stark_verify(&air, &membership_proofs[q * n_folds + m], stark_queries) {
                return false;
            }

            // The fold, a public linear check with the re-derived challenge.
            let half = n >> (m + 1);
            let i = index % half;
            let op = &qp.layers[m];
            let x = (shift * base_omega.pow(i as u64)).pow(1u64 << m);
            let even = (op.a + op.b) * inv2;
            let odd = (op.a - op.b) * inv2 * x.inv();
            let folded = even + betas[m] * odd;

            if m + 1 < n_folds {
                let half_next = n >> (m + 2);
                let next = &qp.layers[m + 1];
                let expected = if i < half_next { next.a } else { next.b };
                if folded != expected {
                    return false;
                }
            } else if folded != final_value {
                return false;
            }
        }
    }

    true
}
