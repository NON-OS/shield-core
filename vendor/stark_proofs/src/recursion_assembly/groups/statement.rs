// NONOS Operating System (AGPL-3.0-or-later)
//! The statement bindings: the out-of-domain point cycled through the transcript
//! squeeze, the compose input, and the periodic recompute (shared); each alpha
//! to the squeeze that drew it and the composition coefficients to the powers
//! region (shared); and comp_z into every query's DEEP check. The point,
//! coefficients, and comp_z are one shared out-of-domain object, so they bind
//! once (z, alphas, coeffs) or once per query (comp_z, to each DEEP claim).

use super::super::layout::Layout;
use super::bind::Bind;
use super::bind::{chain, cycle, group_auto};
use super::roots::absorbed;
use alloc::vec::Vec;

pub fn statement(lay: &Layout, out: &mut Vec<Bind>) {
    let l = lay.l;
    let (zc0, zc1) = (lay.c_z_col, lay.c_z_col + 1);
    // z: squeezed in the transcript, both lanes of one operation == compose's
    // z == the periodic recompute's z.
    let mut zsw = Vec::new();
    if lay.sidecar {
        chain(&[(lay.z_op * l, 0), lay.ccell(zc0)], &mut zsw);
        chain(&[(lay.z_op * l, 1), lay.ccell(zc1)], &mut zsw);
    } else {
        chain(
            &[(lay.z_op * l, 0), lay.ccell(zc0), (lay.pz_off, 4)],
            &mut zsw,
        );
        chain(
            &[(lay.z_op * l, 1), lay.ccell(zc1), (lay.pz_off, 5)],
            &mut zsw,
        );
    }
    out.push(group_auto(lay.span, &zsw));

    // Each alpha == the squeeze that drew it: the powers region carries alpha
    // in columns 2 and 3 of its first row.
    for (op, off) in [(lay.coeff_op, lay.cp_off), (lay.deep_coeff_op, lay.dp_off)] {
        out.push(group_auto(
            lay.span,
            &[(op * l, 0, off, 2), (op * l, 1, off, 3)],
        ));
    }
    // The composition coefficients == the powers, up to two coefficients
    // (four lanes) per group. Row i of the powers region holds alpha^i.
    let mut c = 0;
    while c < lay.n_coeff {
        let take = (lay.n_coeff - c).min(2);
        let mut swaps: Vec<(usize, usize, usize, usize)> = Vec::new();
        for k in 0..take {
            let bc = lay.c_coeff_col + 2 * (c + k);
            let (r0, c0) = lay.ccell(bc);
            let (r1, c1) = lay.ccell(bc + 1);
            swaps.push((lay.cp_off + c + k, 0, r0, c0));
            swaps.push((lay.cp_off + c + k, 1, r1, c1));
        }
        out.push(group_auto(lay.span, &swaps));
        c += take;
    }

    // The inner's permutation challenges == the squeezes that drew them, and
    // their high lanes == the trace chain's pinned zero. The compose region
    // recomputes the inner's grand product at whatever sits in these cells.
    // Two values are beta and gamma, one lane each of consecutive squeezes.
    // Four are their `Fp2` components, both lanes of each squeeze.
    let lanes = if lay.n_chal == 4 { 2 } else { 1 };
    for i in 0..lay.n_chal {
        let bc = lay.c_chal_col + 2 * i;
        let op = lay.beta_op + i / lanes;
        let lane = i % lanes;
        let (r0, c0) = lay.ccell(bc);
        let (r1, c1) = lay.ccell(bc + 1);
        out.push(group_auto(
            lay.span,
            &[(op * l, lane, r0, c0), (lay.ta_off[0], 0, r1, c1)],
        ));
    }

    // The inner's public words: the compose region's input slot == the word
    // the transcript absorbed, which the outer pins to its own public input.
    // The program form reads them from these slots, so the tape carries no
    // statement and one periodic root serves every spend.
    for k in 0..lay.n_pub {
        out.push(cycle(
            lay.span,
            &[lay.ccell(lay.c_pub_col + 2 * k), absorbed(lay, 0, lay.cells.publics[k])],
        ));
    }

    // FRI's seed: the two lanes FRI's transcript absorbed first == the STARK
    // transcript's squeeze after its DEEP draw. Without it FRI's positions,
    // and so the consistency check's, would not depend on the proof above.
    let (s0r, s0c) = absorbed(lay, lay.ft_off, lay.cells.fri_seed[0]);
    let (s1r, s1c) = absorbed(lay, lay.ft_off, lay.cells.fri_seed[1]);
    out.push(group_auto(
        lay.span,
        &[(lay.cells.seed_op * l, 0, s0r, s0c), (lay.cells.seed_op * l, 1, s1r, s1c)],
    ));

    // comp_z: the one composition value == each query's DEEP composition claim.
    let (m0r, m0c) = lay.ccell(lay.c_comp_z_col);
    let (m1r, m1c) = lay.ccell(lay.c_comp_z_col + 1);
    for q in 0..lay.n_q {
        out.push(group_auto(
            lay.span,
            &[(m0r, m0c, lay.d_off[q], 4), (m1r, m1c, lay.d_off[q], 5)],
        ));
    }
}
