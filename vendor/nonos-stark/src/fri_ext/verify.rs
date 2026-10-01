// NONOS Operating System (AGPL-3.0-or-later)

//! The money-grade FRI verifier. It rebuilds the transcript, draws each fold
//! challenge from the extension, checks the grinding proof-of-work, and for every
//! sampled query re-derives the extension fold and binds each opened value by a
//! Merkle path. It only reads the proof and never panics.

use super::super::field::Fp;
use super::super::field::Fp2;
use super::super::fri::FOLD;
use super::super::fri::{final_log, final_point, horner, n_layers, root_of_unity, FRI_FOLD_LOG};
use super::super::merkle::verify_path_group;
use super::super::transcript::Transcript;
use super::types::FriProofExt;
use alloc::vec::Vec;

/// Verify a money-grade FRI proof. Returns `true` only if every structural,
/// grinding, Merkle, folding, and low-degree check passes for all queries.
pub fn fri_verify_ext(
    proof: &FriProofExt,
    shift: Fp,
    log_n: u32,
    log_blowup: u32,
    n_queries: usize,
    grind_bits: u32,
) -> bool {
    fri_verify_ext_seeded(proof, shift, log_n, log_blowup, n_queries, grind_bits, None).is_some()
}

/// `fri_verify_ext` under a STARK's seed, absorbed where the prover absorbed
/// it, before layer zero. Returns the positions it checked when it accepts,
/// in draw order, for the STARK's consistency check to run at; `None` when it
/// refuses. A position is only returned once its whole chain has checked.
pub fn fri_verify_ext_seeded(
    proof: &FriProofExt,
    shift: Fp,
    log_n: u32,
    log_blowup: u32,
    n_queries: usize,
    grind_bits: u32,
    seed: Option<&[u8; 32]>,
) -> Option<Vec<usize>> {
    fri_verify_ext_seeded_ground(
        proof, shift, log_n, log_blowup, n_queries, grind_bits, 0, 1, seed,
    )
}

/// `fri_verify_ext_seeded`, requiring `commit_grind` bits of proof-of-work on
/// the nonce before each folding challenge, one nonce per layer. Zero requires
/// that the proof carries none. `grind_chunks` is the split of the query grind
/// the parameter set fixes: that many nonces, each checked at
/// `grind_bits - log2(grind_chunks)` bits against the transcript with the one
/// before it absorbed. The count is the caller's, never the proof's.
#[allow(clippy::too_many_arguments)]
pub fn fri_verify_ext_seeded_ground(
    proof: &FriProofExt,
    shift: Fp,
    log_n: u32,
    log_blowup: u32,
    n_queries: usize,
    grind_bits: u32,
    commit_grind: u32,
    grind_chunks: u32,
    seed: Option<&[u8; 32]>,
) -> Option<Vec<usize>> {
    let n = 1usize << log_n;
    let n_layers = n_layers(log_n, log_blowup);
    let n_folds = n_layers * FRI_FOLD_LOG as usize;

    if proof.roots.len() != n_layers
        || proof.final_layer.len() != 1usize << final_log(log_n, log_blowup)
        || proof.queries.len() != n_queries
        || proof.fold_nonces.len() != if commit_grind > 0 { n_layers } else { 0 }
        || proof.pow_chain.len() + 1 != grind_chunks.max(1) as usize
    {
        return None;
    }

    // v2, on the launch transcript: only the accepted shapes, each at its
    // own grind.
    #[cfg(feature = "v2")]
    if grind_chunks > 1 && !super::shape_accepts(n_queries, grind_bits) {
        return None;
    }

    let base_omega = root_of_unity(log_n);
    let inv2 = Fp::from_u64(2).inv();

    let mut transcript = Transcript::new(b"NONOS-STARK-FRI-EXT");
    if let Some(seed) = seed {
        transcript.absorb_digest(seed);
    }
    let mut betas: Vec<Fp2> = Vec::with_capacity(n_layers);
    for (m, root) in proof.roots.iter().enumerate() {
        transcript.absorb_digest(root);
        if commit_grind > 0 && !transcript.verify_pow(proof.fold_nonces[m], commit_grind) {
            return None;
        }
        betas.push(transcript.challenge_fp2());
    }

    // The low-degree conclusion: the final layer must be a single constant.
    transcript.absorb_fp2_vec(&proof.final_layer);
    // The shape comes from this verifier's own parameters, which the length
    // checks above already hold the proof to (queries == n_queries, nonces ==
    // grind_chunks), never from a count read off the proof.
    #[cfg(feature = "v2")]
    if grind_chunks > 1 {
        transcript.absorb_shape(super::shape_id(n_queries));
    }

    // The grinding nonces must meet the proof-of-work, bound at the same
    // transcript points the prover committed them, before any query position
    // is drawn: each against the state with the one before it absorbed.
    let per_chunk = super::prove::chunk_bits(grind_bits, grind_chunks);
    for &nonce in core::iter::once(&proof.pow_nonce).chain(&proof.pow_chain) {
        if !transcript.verify_pow(nonce, per_chunk) {
            return None;
        }
    }

    let mut positions: Vec<usize> = Vec::with_capacity(n_queries);
    for qp in &proof.queries {
        if qp.layers.len() != n_layers {
            return None;
        }
        let q = transcript.challenge_index(n);
        positions.push(q);
        for (m, beta) in betas.iter().enumerate() {
            let halvings = m * FRI_FOLD_LOG as usize;
            let size = n >> halvings;
            let stride = size >> FRI_FOLD_LOG;
            let i = q % stride;
            let op = &qp.layers[m];

            if !verify_path_group(&proof.roots[m], i, &op.v, &op.path) {
                return None;
            }

            /*
             * A layer is FRI_FOLD_LOG halvings under beta, beta^2, beta^4 and
             * so on. Slot j of the group is position i + j * stride. The first
             * halving pairs slot j with slot j + FOLD / 2, half the layer away,
             * at slot j's point; the results form the same structure on the
             * squared domain with half the slots, and so on down to one value.
             * Every point is the layer's own coset raised to the halvings
             * already taken. At radix 4 this is exactly the two folds it was.
             */
            let fold = |a: Fp2, b: Fp2, x: Fp, beta: Fp2| -> Fp2 {
                let even = (a + b).mul_base(inv2);
                let odd = (a - b).mul_base(inv2).mul_base(x.inv());
                even + beta * odd
            };
            let mut vals: [Fp2; FOLD] = op.v;
            let mut xs: [Fp; FOLD] = core::array::from_fn(|j| {
                (shift * base_omega.pow((i + j * stride) as u64)).pow(1u64 << halvings)
            });
            let mut b = *beta;
            let mut width = FOLD;
            while width > 1 {
                let half = width / 2;
                for j in 0..half {
                    vals[j] = fold(vals[j], vals[j + half], xs[j], b);
                    xs[j] = xs[j] * xs[j];
                }
                width = half;
                b = b * b;
            }
            let folded = vals[0];

            if m + 1 < n_layers {
                // On the next layer the position is `i` and its group starts
                // at `i` modulo that layer's own stride.
                let next_stride = stride >> FRI_FOLD_LOG;
                let next = &qp.layers[m + 1];
                let expected = next.v[(i / next_stride) % FOLD];
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

/// One query's final point and the final polynomial's value there, in the
/// verifier's own order: what a verifier being ported holds its Horner
/// against. Replays the transcript exactly as `fri_verify_ext` does and
/// checks nothing else; a proof that does not verify gives values that
/// mean nothing, so verify first.
pub fn fri_final_vector_ext(
    proof: &FriProofExt,
    shift: Fp,
    log_n: u32,
    log_blowup: u32,
    grind_bits: u32,
    seed: Option<&[u8; 32]>,
) -> Vec<(usize, Fp2, Fp2)> {
    let n = 1usize << log_n;
    let n_folds = n_layers(log_n, log_blowup) * FRI_FOLD_LOG as usize;
    let base_omega = root_of_unity(log_n);
    let mut transcript = Transcript::new(b"NONOS-STARK-FRI-EXT");
    if let Some(seed) = seed {
        transcript.absorb_digest(seed);
    }
    for (m, root) in proof.roots.iter().enumerate() {
        transcript.absorb_digest(root);
        if let Some(&nonce) = proof.fold_nonces.get(m) {
            transcript.verify_pow(nonce, 0);
        }
        transcript.challenge_fp2();
    }
    transcript.absorb_fp2_vec(&proof.final_layer);
    #[cfg(feature = "v2")]
    if !proof.pow_chain.is_empty() {
        transcript.absorb_shape(super::shape_id(proof.queries.len()));
    }
    // The split is read off the proof here: this helper runs only on a proof
    // already verified at its parameter set, and checks nothing of its own.
    let per_chunk = super::prove::chunk_bits(grind_bits, proof.pow_chain.len() as u32 + 1);
    for &nonce in core::iter::once(&proof.pow_nonce).chain(&proof.pow_chain) {
        if !transcript.verify_pow(nonce, per_chunk) {
            return Vec::new();
        }
    }
    proof
        .queries
        .iter()
        .map(|_| {
            let q = transcript.challenge_index(n);
            let x_final = final_point(shift, base_omega, q % (n >> n_folds), n_folds);
            (q, x_final, horner(&proof.final_layer, x_final))
        })
        .collect()
}

/// The positions FRI draws for `proof` under `seed`, replayed and checked
/// against nothing: the nonce is absorbed where it was committed, whatever it
/// is worth. For a consumer rederiving what the prover drew; a verifier calls
/// `fri_verify_ext_seeded`, which returns the same positions only when the
/// proof holds.
pub fn fri_positions_ext(proof: &FriProofExt, log_n: u32, seed: Option<&[u8; 32]>) -> Vec<usize> {
    let n = 1usize << log_n;
    let mut transcript = Transcript::new(b"NONOS-STARK-FRI-EXT");
    if let Some(seed) = seed {
        transcript.absorb_digest(seed);
    }
    for (m, root) in proof.roots.iter().enumerate() {
        transcript.absorb_digest(root);
        if let Some(&nonce) = proof.fold_nonces.get(m) {
            transcript.verify_pow(nonce, 0);
        }
        transcript.challenge_fp2();
    }
    transcript.absorb_fp2_vec(&proof.final_layer);
    #[cfg(feature = "v2")]
    if !proof.pow_chain.is_empty() {
        transcript.absorb_shape(super::shape_id(proof.queries.len()));
    }
    for &nonce in core::iter::once(&proof.pow_nonce).chain(&proof.pow_chain) {
        transcript.verify_pow(nonce, 0);
    }
    proof
        .queries
        .iter()
        .map(|_| transcript.challenge_index(n))
        .collect()
}

/// The fold challenges FRI drew for `proof` under `seed`, replayed and
/// checked against nothing, one per layer: what a consumer rederiving the
/// FRI's linear maps needs, beside the positions.
pub fn fri_fold_challenges_ext(proof: &FriProofExt, seed: Option<&[u8; 32]>) -> Vec<Fp2> {
    let mut transcript = Transcript::new(b"NONOS-STARK-FRI-EXT");
    if let Some(seed) = seed {
        transcript.absorb_digest(seed);
    }
    let mut betas = Vec::with_capacity(proof.roots.len());
    for (m, root) in proof.roots.iter().enumerate() {
        transcript.absorb_digest(root);
        if let Some(&nonce) = proof.fold_nonces.get(m) {
            transcript.verify_pow(nonce, 0);
        }
        betas.push(transcript.challenge_fp2());
    }
    betas
}
