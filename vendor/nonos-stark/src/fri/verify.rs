// NONOS Operating System (AGPL-3.0-or-later)

//! The FRI verifier. It never trusts the prover: it recomputes the transcript,
//! checks the final layer is constant, and for each sampled query re-derives the
//! fold and checks it against the next committed layer, every value bound by a
//! Merkle path. It only reads the proof and never panics.

use super::super::field::Fp;
use super::super::merkle::verify_path;
use super::super::transcript::Transcript;
use super::domain::root_of_unity;
use super::types::FriProof;
use alloc::vec::Vec;

/// Verify a FRI proof for a size-`2^log_n` domain and blowup `2^log_blowup`.
/// Returns `true` only if every structural, Merkle, folding, and low-degree
/// check passes for all `n_queries` sampled positions.
pub fn fri_verify(
    proof: &FriProof,
    shift: Fp,
    log_n: u32,
    log_blowup: u32,
    n_queries: usize,
) -> bool {
    let n = 1usize << log_n;
    let blowup = 1usize << log_blowup;
    let n_folds = (log_n - log_blowup) as usize;

    if proof.roots.len() != n_folds
        || proof.final_layer.len() != blowup
        || proof.queries.len() != n_queries
    {
        return false;
    }

    let base_omega = root_of_unity(log_n);
    let inv2 = Fp::from_u64(2).inv();

    // Rebuild the transcript exactly as the prover did: absorb each root and
    // draw its fold challenge, then absorb the final layer.
    let mut transcript = Transcript::new(b"NONOS-STARK-FRI");
    let mut betas: Vec<Fp> = Vec::with_capacity(n_folds);
    for root in &proof.roots {
        transcript.absorb_digest(root);
        betas.push(transcript.challenge_fp());
    }

    // The low-degree conclusion: the final layer must be a single constant.
    let final_value = proof.final_layer[0];
    if proof.final_layer.iter().any(|v| *v != final_value) {
        return false;
    }
    transcript.absorb_fp_vec(&proof.final_layer);

    for qp in &proof.queries {
        if qp.layers.len() != n_folds {
            return false;
        }
        let q = transcript.challenge_index(n);
        for (m, beta) in betas.iter().enumerate() {
            let half = n >> (m + 1);
            let i = q % half;
            let op = &qp.layers[m];

            // Bind both opened points to this layer's commitment.
            if !verify_path(&proof.roots[m], i, op.a, &op.a_path)
                || !verify_path(&proof.roots[m], i + half, op.b, &op.b_path)
            {
                return false;
            }

            // Recompute the fold at the queried point of layer m, which is
            // `(shift * omega^i)^(2^m)` on the squared coset.
            let x = (shift * base_omega.pow(i as u64)).pow(1u64 << m);
            let even = (op.a + op.b) * inv2;
            let odd = (op.a - op.b) * inv2 * x.inv();
            let folded = even + *beta * odd;

            // The fold must equal the value at the same index one layer up.
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
