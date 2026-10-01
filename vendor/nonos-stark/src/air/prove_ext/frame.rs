// NONOS Operating System (AGPL-3.0-or-later)

//! The out-of-domain frame: the trace window, the periodic columns, and the composition all
//! evaluated at the sampled point z. `ood_frame` reads each trace column at z and its shifts,
//! `periodic_at_z` the periodic columns, and `comp_at_z` the composition value the DEEP check
//! consumes. These are the claims the prover absorbs into the transcript and the verifier
//! recomputes, so the frame is the hinge between the composition check and the DEEP quotients.

use super::super::super::field::{Fp, Fp2};
use super::super::super::poly::{eval_cols_on_subgroup_ext, eval_ext};
use super::super::composition::compose_ext;
use super::super::spec::AirExt;
use super::setup::Domain;
use alloc::vec::Vec;

/// The out-of-domain trace frame: every column at z * g^k for each window row,
/// straight from the coefficients.
pub(in crate::air) fn ood_frame(trace: &[Vec<Fp>], d: &Domain, z: Fp2) -> Vec<Fp2> {
    let mut frame = Vec::with_capacity(d.window * d.width);
    for k in 0..d.window {
        let zk = z * Fp2::from_base(d.g.pow(k as u64));
        for coeffs_c in trace {
            frame.push(eval_ext(coeffs_c, zk));
        }
    }
    frame
}

/// The periodic columns interpolated at z over the trace domain: the values
/// the composition at z consumes, and in the preprocessed form the claims the
/// sidecar carries.
pub(in crate::air) fn periodic_at_z(d: &Domain, cols: &[Vec<Fp>], z: Fp2) -> Vec<Fp2> {
    eval_cols_on_subgroup_ext(d.g, d.t, cols, z)
}

/// The composition at z from the claimed frame and periodic values: the same
/// batching the domain pass ran, at the out-of-domain point.
pub(in crate::air) fn comp_at_z<A: AirExt>(
    air: &A,
    d: &Domain,
    frame: &[Fp2],
    periodic_z: &[Fp2],
    z: Fp2,
    coeffs: &[Fp2],
) -> Fp2 {
    compose_ext(air, d.g, z, frame, periodic_z, coeffs)
}
