// NONOS Operating System (AGPL-3.0-or-later)
//! Region 3 (the FRI transcript, shared across queries) and region 4 (the fold
//! chain, one per query). The transcript replays the whole FRI verifier's
//! sponge: the root absorbs and beta squeezes, the final polynomial's
//! coefficients, the grinding nonce, and every query index draw; each fold
//! carries the per-layer points, inverses, and position bits the
//! square-and-sign chain derives from its query index `q_k`.

use super::inner::{Inner, LOG_ROUNDS};
use super::sponge::{OpCell, Recorder};
use super::tamper::Tamper;
use crate::crypto::stark::air::{AirExt, Poseidon, TraceFoldExt, TranscriptCheck, RATE};
use crate::crypto::stark::field::{Fp, Fp2};
use crate::crypto::stark::fri::{final_point, horner, root_of_unity};
use alloc::vec::Vec;

/// The shared FRI transcript region and the per-query indices it draws.
pub struct FriTranscript {
    pub transcript: TranscriptCheck,
    pub ttrace: Vec<Fp>,
    pub betas: Vec<Fp2>,
    /// The operation reading each beta, both lanes.
    pub beta_ops: Vec<usize>,
    /// The seed's absorbed lanes, `c0` then `c1`: bound to the STARK
    /// transcript's squeeze of it.
    pub seed_cells: [OpCell; 2],
    /// The first root's absorbed lanes: what layer zero's openings anchor to.
    pub root0: [OpCell; RATE],
    /// The final polynomial's absorbed lanes, `c0` then `c1` per coefficient.
    pub coeff_cells: Vec<OpCell>,
    pub n_folds: usize,
    pub log_n: u32,
    /// Every FRI query index, drawn consecutively after the proof of work: the
    /// operation, the element it read, and the index.
    pub index_ops: Vec<usize>,
    pub index_values: Vec<u64>,
    pub qs: Vec<usize>,
}

/// `seed` is the STARK transcript's squeeze after its DEEP draw
/// (`StarkTranscript::seed`), absorbed before layer zero.
pub fn fri_transcript<A: AirExt>(h: &Poseidon, inner: &Inner<A>, seed: Fp2) -> FriTranscript {
    let fri = &inner.proof.fri;
    let n_folds = fri.roots.len();
    /*
     * The final layer is the final polynomial's 2^k coefficients, so the
     * domain is the folds, the blowup and k together; the blowup is the
     * inner's at the rate it was proved at.
     */
    assert!(fri.final_layer.len().is_power_of_two(), "the final polynomial has 2^k coefficients");
    let k = fri.final_layer.len().trailing_zeros();
    let (_, log_blowup) = crate::crypto::stark::air::domain_params_blown(&inner.air, inner.extra);
    let log_n = n_folds as u32 + log_blowup + k;
    let n = 1usize << log_n;

    let mut r = Recorder::new(h);
    let seed_cells = [r.absorb(seed.c0), r.absorb(seed.c1)];
    let mut betas: Vec<Fp2> = Vec::with_capacity(n_folds);
    let mut beta_ops: Vec<usize> = Vec::with_capacity(n_folds);
    let mut root0 = [(0, 0); RATE];
    for (m, root) in fri.roots.iter().enumerate() {
        let cells = r.absorb_digest(root);
        if m == 0 {
            root0 = cells;
        }
        let (op, beta) = r.challenge_fp2();
        beta_ops.push(op);
        betas.push(beta);
    }
    let mut coeff_cells = Vec::with_capacity(2 * fri.final_layer.len());
    for value in &fri.final_layer {
        coeff_cells.push(r.absorb(value.c0));
        coeff_cells.push(r.absorb(value.c1));
    }
    assert!(r.verify_pow(fri.pow_nonce, inner.grind), "the FRI proof-of-work did not check");
    // One index per FRI query, drawn in order; qs[k] is query k's fold position.
    let n_q = fri.queries.len();
    let (mut index_ops, mut index_values, mut qs) =
        (Vec::with_capacity(n_q), Vec::with_capacity(n_q), Vec::with_capacity(n_q));
    for _ in 0..n_q {
        let (op, v, q) = r.challenge_index(n);
        index_ops.push(op);
        index_values.push(v.value());
        qs.push(q);
    }
    let transcript = TranscriptCheck::new_witness(h.clone(), LOG_ROUNDS, r.finish());
    let ttrace = transcript.trace();

    FriTranscript {
        transcript,
        ttrace,
        betas,
        beta_ops,
        seed_cells,
        root0,
        coeff_cells,
        n_folds,
        log_n,
        index_ops,
        index_values,
        qs,
    }
}

/// One query's fold chain (region 4), derived from its index `q_k`.
pub struct FoldSide {
    pub fold: TraceFoldExt,
    pub ftrace: Vec<Fp>,
    /// The layer-zero position of this query: `q_k mod (n / 2)`.
    pub ik: usize,
}

pub fn fri_fold_k<A: AirExt>(
    inner: &Inner<A>,
    ft: &FriTranscript,
    query: usize,
    tamper: Tamper,
) -> FoldSide {
    let fri = &inner.proof.fri;
    let n = 1usize << ft.log_n;
    let qk = ft.qs[query];
    let bo = root_of_unity(ft.log_n);
    let shift = Fp::from_u64(7);
    // This query's final value: the final polynomial at its last point.
    let final_value = horner(&fri.final_layer, final_point(shift, bo, qk % (n >> ft.n_folds), ft.n_folds));
    let (mut a, mut b, mut xi, mut dir) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for (m, op) in fri.queries[query].layers.iter().enumerate() {
        a.push(op.a);
        b.push(op.b);
        let ix = qk % (n >> (m + 1));
        xi.push((shift * bo.pow(ix as u64)).pow(1u64 << m).inv());
        dir.push(ix >= (n >> (m + 2)));
    }
    a.push(final_value);
    b.push(final_value);
    let log_layers = (ft.n_folds + 1).next_power_of_two().trailing_zeros();
    let fold = TraceFoldExt::new_witness(log_layers, ft.n_folds, xi, dir, final_value);
    let betas = match tamper {
        Tamper::OffTranscriptBeta => {
            let mut v = ft.betas.clone();
            v[0] = v[0] + Fp2::ONE;
            v
        }
        _ => ft.betas.clone(),
    };
    let ftrace = fold.trace(&betas, &a, &b);
    FoldSide {
        fold,
        ftrace,
        ik: qk % (n >> 1),
    }
}

/// The query-0 combined form the current single-query `assemble()` consumes. Built
/// from the shared transcript plus query 0's fold, so its behavior is unchanged.
pub struct FriSide {
    pub transcript: TranscriptCheck,
    pub ttrace: Vec<Fp>,
    pub fold: TraceFoldExt,
    pub ftrace: Vec<Fp>,
    pub n_folds: usize,
    pub log_n: u32,
    /// The layer-zero position of query zero: q0 mod (n / 2).
    pub i0: usize,
}

pub fn fri_side<A: AirExt>(h: &Poseidon, inner: &Inner<A>, tamper: Tamper) -> FriSide {
    let ft = fri_transcript(h, inner, super::transcript::stark_transcript(h, inner).seed);
    let f0 = fri_fold_k(inner, &ft, 0, tamper);
    FriSide {
        transcript: ft.transcript,
        ttrace: ft.ttrace,
        fold: f0.fold,
        ftrace: f0.ftrace,
        n_folds: ft.n_folds,
        log_n: ft.log_n,
        i0: f0.ik,
    }
}
