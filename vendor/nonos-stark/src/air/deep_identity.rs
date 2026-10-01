// NONOS Operating System (AGPL-3.0-or-later)

//! The batched DEEP value at one query, written once.
//!
//! Every preprocessed verifier forms the same sum: one quotient per frame cell
//! against its claim, one for the composition, one per periodic column against
//! its claim, each under its own coefficient. Two verifiers that form it two
//! ways are two places for a coefficient order to drift.

use super::super::field::{Fp, Fp2};

/// Where the query sits: the out-of-domain point, the trace-domain generator,
/// the evaluation point, and the frame's shape.
pub struct At {
    pub z: Fp2,
    pub g: Fp,
    pub x: Fp,
    pub width: usize,
    pub window: usize,
}

/// The values the query opens, in the order the coefficients were drawn.
pub struct Opened<'a> {
    pub frame: &'a [Fp2],
    pub trace: &'a [Fp],
    pub comp: Fp2,
    pub comp_z: Fp2,
    pub row: &'a [Fp],
    pub periodic_z: &'a [Fp2],
}

pub fn batched(at: &At, coeffs: &[Fp2], o: &Opened) -> Fp2 {
    let xe = Fp2::from_base(at.x);
    let mut acc = Fp2::ZERO;
    for k in 0..at.window {
        let zk = at.z * Fp2::from_base(at.g.pow(k as u64));
        let inv = (xe - zk).inv();
        for c in 0..at.width {
            let claimed = o.frame[k * at.width + c];
            acc = acc + coeffs[k * at.width + c] * ((Fp2::from_base(o.trace[c]) - claimed) * inv);
        }
    }
    let inv_x_z = (xe - at.z).inv();
    let base = at.width * at.window;
    acc = acc + coeffs[base] * ((o.comp - o.comp_z) * inv_x_z);
    for (i, &v) in o.row.iter().enumerate() {
        acc = acc + coeffs[base + 1 + i] * ((Fp2::from_base(v) - o.periodic_z[i]) * inv_x_z);
    }
    acc
}
