// NONOS Operating System (AGPL-3.0-or-later)

//! The Poseidon-committed money-grade FRI verifier: it replays the Poseidon
//! transcript, checks each layer's Poseidon Merkle openings, and re-runs the
//! extension fold to the constant final layer. It is the exact algorithm the
//! recursive verifier arithmetizes, so an honest inner proof re-verified here also
//! verifies in-circuit.

use super::super::air::Poseidon;
use super::super::field::{Fp, Fp2};
use super::super::fri::{final_point, horner, n_folds as folds_of, root_of_unity, stop_log};
use super::super::poseidon_merkle::{pack_pair_ext, verify_path};
use super::super::poseidon_transcript::PoseidonTranscript;
use super::types::FriProofExtP;
use alloc::vec::Vec;

pub fn fri_verify_poseidon_ext(
    proof: &FriProofExtP,
    shift: Fp,
    log_n: u32,
    log_blowup: u32,
    n_queries: usize,
    grind_bits: u32,
    hasher: &Poseidon,
) -> bool {
    fri_verify_poseidon_ext_seeded(proof, shift, log_n, log_blowup, n_queries, grind_bits, hasher, None)
        .is_some()
}

/// `fri_verify_poseidon_ext` under a STARK's seed, absorbed where the prover
/// absorbed it. Returns the positions it checked, in draw order, when it
/// accepts, for the STARK's consistency check to run at; `None` when it
/// refuses.
#[allow(clippy::too_many_arguments)]
pub fn fri_verify_poseidon_ext_seeded(
    proof: &FriProofExtP,
    shift: Fp,
    log_n: u32,
    log_blowup: u32,
    n_queries: usize,
    grind_bits: u32,
    hasher: &Poseidon,
    seed: Option<[Fp; 2]>,
) -> Option<Vec<usize>> {
    let n = 1usize << log_n;
    let n_folds = folds_of(log_n, log_blowup);
    if proof.roots.len() != n_folds
        || proof.final_layer.len() != 1usize << stop_log(log_n, log_blowup)
        || proof.queries.len() != n_queries
    {
        return None;
    }
    let base_omega = root_of_unity(log_n);
    let inv2 = Fp::from_u64(2).inv();

    let mut transcript = PoseidonTranscript::new(hasher.clone());
    if let Some([s0, s1]) = seed {
        transcript.absorb(s0);
        transcript.absorb(s1);
    }
    let mut betas: Vec<Fp2> = Vec::with_capacity(n_folds);
    for root in &proof.roots {
        transcript.absorb_digest(root);
        betas.push(transcript.challenge_fp2());
    }

    for value in &proof.final_layer {
        transcript.absorb(value.c0);
        transcript.absorb(value.c1);
    }
    if !transcript.verify_pow(proof.pow_nonce, grind_bits) {
        return None;
    }

    let mut positions: Vec<usize> = Vec::with_capacity(n_queries);
    for qp in &proof.queries {
        if qp.layers.len() != n_folds {
            return None;
        }
        let q = transcript.challenge_index(n);
        positions.push(q);
        for (m, beta) in betas.iter().enumerate() {
            let half = n >> (m + 1);
            let i = q % half;
            let op = &qp.layers[m];

            /*
             * One path over the leaf the fold reads. The index is a position in
             * a tree of `half` leaves, so it is `q % half` and never
             * `q >> (m + 1)`: those agree whenever the query falls in the low
             * half, which is most of the time at the early layers, and diverge
             * above it. A shift would pass the first layers of most queries and
             * fail deep ones, which presents as a flaky prover.
             */
            if !verify_path(hasher, &proof.roots[m], i, pack_pair_ext(op.a, op.b), &op.path) {
                return None;
            }

            let x = (shift * base_omega.pow(i as u64)).pow(1u64 << m);
            let even = (op.a + op.b).mul_base(inv2);
            let odd = (op.a - op.b).mul_base(inv2).mul_base(x.inv());
            let folded = even + *beta * odd;

            if m + 1 < n_folds {
                let half_next = n >> (m + 2);
                let next = &qp.layers[m + 1];
                let expected = if i < half_next { next.a } else { next.b };
                if folded != expected {
                    return None;
                }
            } else {
                // The last fold lands on the final polynomial at this query's point.
                let x_final = final_point(shift, base_omega, q % (n >> n_folds), n_folds);
                if folded != horner(&proof.final_layer, x_final) {
                    return None;
                }
            }
        }
    }

    Some(positions)
}

/// The positions FRI draws for `proof` under `seed`, replayed and checked
/// against nothing, for a consumer rederiving what the prover drew. A
/// verifier calls `fri_verify_poseidon_ext_seeded`, which returns the same
/// positions only when the proof holds.
pub fn fri_positions_poseidon(
    proof: &FriProofExtP,
    log_n: u32,
    hasher: &Poseidon,
    seed: Option<[Fp; 2]>,
) -> Vec<usize> {
    let n = 1usize << log_n;
    let mut transcript = PoseidonTranscript::new(hasher.clone());
    if let Some([s0, s1]) = seed {
        transcript.absorb(s0);
        transcript.absorb(s1);
    }
    for root in &proof.roots {
        transcript.absorb_digest(root);
        transcript.challenge_fp2();
    }
    for value in &proof.final_layer {
        transcript.absorb(value.c0);
        transcript.absorb(value.c1);
    }
    transcript.verify_pow(proof.pow_nonce, 0);
    proof.queries.iter().map(|_| transcript.challenge_index(n)).collect()
}
