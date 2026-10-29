// NONOS Operating System (AGPL-3.0-or-later)

//! The DEEP polynomial over the evaluation domain. It combines the trace and composition
//! evaluations into quotients that are low degree exactly when the claimed out-of-domain
//! values are correct: each quotient subtracts the claim and divides by the point's vanishing
//! factor, so a wrong claim leaves a pole and fails the low-degree test. The result is what
//! FRI folds, and it ties the sampled trace values to the out-of-domain frame the composition
//! was checked against.

use super::super::super::field::{Fp, Fp2};
use super::super::super::poly::batch_inv;
use super::compose::BLOCK;
use super::super::super::poly::lde_from_coeffs;
use super::commit::COSET_BATCH;
use super::setup::Domain;
use alloc::vec::Vec;

/// The DEEP polynomial over the domain: every trace quotient against the
/// claimed frame, plus the composition quotient, batched under the DEEP
/// coefficients. Coset-walked like the composition, and the trace columns are
/// extended a second time here rather than kept, because the extension is
/// cheaper than holding width times the domain in memory ever was.
#[allow(clippy::too_many_arguments)]
pub(in crate::air) fn over_domain(
    d: &Domain,
    trace: &[Vec<Fp>],
    comp_d: &[Fp2],
    ood_frame: &[Fp2],
    comp_z: Fp2,
    z: Fp2,
    deep_coeffs: &[Fp2],
) -> Vec<Fp2> {
    // z * g^k once per window row, not once per point.
    let zks: Vec<Fp2> = (0..d.window)
        .map(|k| z * Fp2::from_base(d.g.pow(k as u64)))
        .collect();
    let e = deep_coeffs[d.width * d.window];

    let mut deep_d = alloc::vec![Fp2::ZERO; d.n];
    // Cosets a batch at a time, as the trace commitment goes: one map over
    // every column of every coset in the batch, then one over every block.
    let w = trace.len();
    let batch = COSET_BATCH.min(d.blowup).max(1);
    let blocks = d.t.div_ceil(BLOCK);
    for c0 in (0..d.blowup).step_by(batch) {
        let nc = batch.min(d.blowup - c0);
        let ext: Vec<Vec<Fp>> = crate::par::map_index(nc * w, |k| {
            let (ci, j) = (k / w, k % w);
            lde_from_coeffs(&trace[j], d.coset_shift(c0 + ci), d.sub, d.t)
        });
        let parts = crate::par::map_index(nc * blocks, |k| {
            let (ci, b) = (k / blocks, k % blocks);
            let c = c0 + ci;
            let cols = &ext[ci * w..(ci + 1) * w];
            let shift_c = d.coset_shift(c);
            let (lo, hi) = (b * BLOCK, ((b + 1) * BLOCK).min(d.t));
            // Every denominator in the block at once: window + 1 of them per
            // point, one field inversion for all of them together.
            let stride = zks.len() + 1;
            let mut dens: Vec<Fp2> = Vec::with_capacity((hi - lo) * stride);
            let mut x = shift_c * d.sub.pow(lo as u64);
            for _ in lo..hi {
                let xe = Fp2::from_base(x);
                for zk in &zks {
                    dens.push(xe - *zk);
                }
                dens.push(xe - z);
                x = x * d.sub;
            }
            let invs = batch_inv(&dens);

            let mut out: Vec<Fp2> = Vec::with_capacity(hi - lo);
            for i in lo..hi {
                let j = c + d.blowup * i;
                let base = (i - lo) * stride;
                let mut acc = Fp2::ZERO;
                for k in 0..zks.len() {
                    let inv_x_zk = invs[base + k];
                    for (col, column) in cols.iter().enumerate() {
                        let claimed = ood_frame[k * d.width + col];
                        acc = acc
                            + deep_coeffs[k * d.width + col]
                                * ((Fp2::from_base(column[i]) - claimed) * inv_x_zk);
                    }
                }
                acc = acc + e * ((comp_d[j] - comp_z) * invs[base + zks.len()]);
                out.push(acc);
            }
            out
        });
        for (k, part) in parts.into_iter().enumerate() {
            let (ci, b) = (k / blocks, k % blocks);
            for (r, v) in part.into_iter().enumerate() {
                deep_d[c0 + ci + d.blowup * (b * BLOCK + r)] = v;
            }
        }
    }
    deep_d
}
