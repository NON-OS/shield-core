// NONOS Operating System (AGPL-3.0-or-later)
//! The fold bindings, one block per inner query: the betas to their (shared)
//! transcript squeezes, query q's layer-zero opened value to q's authenticated
//! FRI leaf, q's final value to the final polynomial evaluated at q's last
//! point, and the point provenance: q's layer-zero x seeded by q's FRI draw,
//! whose bits are q's own fold position bits and q's leaf opening path
//! directions.

use super::super::layout::Layout;
use super::bind::Bind;
use super::bind::{chain, group, labeled};
use super::roots::absorbed;
use crate::crypto::stark::air::Horner;
use alloc::vec::Vec;

pub fn fold(lay: &Layout, out: &mut Vec<Bind>) {
    let l = lay.l;
    for q in 0..lay.n_q {
        let f_off = lay.f_off[q];
        let m_off = lay.m_off[q];
        let fp_off = lay.fp_off[q];
        let h_off = lay.h_off[q];

        // Each beta == the two lanes of the FRI transcript operation that read it.
        let mut bsw: Vec<(usize, usize, usize, usize)> = Vec::new();
        for m in 0..lay.n_folds {
            let row = lay.ft_off + lay.cells.fri_beta_ops[m] * l;
            bsw.push((row, 0, f_off + m, 0));
            bsw.push((row, 1, f_off + m, 1));
        }
        out.push(group(lay.span, alloc::vec![0, 1], &bsw));

        /*
         * The last fold lands on the final polynomial at this query's point:
         * the value the row after the last fold carries == the Horner region's
         * result, the Horner point == the fold chain's final point, and every
         * coefficient the Horner region reads == the lane the FRI transcript
         * absorbed it in, shared by every query.
         */
        let last = f_off + lay.n_folds;
        let hv = h_off + lay.horner_value_row;
        out.push(labeled(
            "final",
            lay.span,
            alloc::vec![2, 3, Horner::ACC, Horner::ACC + 1],
            &[(last, 2, hv, Horner::ACC), (last, 3, hv, Horner::ACC + 1)],
        ));
        out.push(labeled("final_x", lay.span, alloc::vec![6, Horner::X], &[(last, 6, h_off, Horner::X)]));
        let mut csw: Vec<(usize, usize, usize, usize)> = Vec::new();
        for i in 0..lay.n_final {
            let row = h_off + lay.n_final - 1 - i;
            let (r0, c0) = absorbed(lay, lay.ft_off, lay.cells.fri_coeff_cells[2 * i]);
            let (r1, c1) = absorbed(lay, lay.ft_off, lay.cells.fri_coeff_cells[2 * i + 1]);
            csw.push((row, Horner::COEFF, r0, c0));
            csw.push((row, Horner::COEFF + 1, r1, c1));
        }
        let mut ccols: Vec<usize> = csw.iter().flat_map(|&(_, a, _, b)| [a, b]).collect();
        ccols.sort_unstable();
        ccols.dedup();
        out.push(labeled("final_coeffs", lay.span, ccols, &csw));

        let (mr, mc) = (m_off + lay.ocells[q][0].0, lay.ocells[q][0].1);
        out.push(group(
            lay.span,
            alloc::vec![2, 3, mc, mc + 1],
            &[(f_off, 2, mr, mc), (f_off, 3, mr, mc + 1)],
        ));

        // The layer-zero point == query q's FRI draw walked to shift * omega^i_k,
        // so the square-and-sign chain descends from q's drawn index; and the
        // draw's recovered element == the FRI transcript cell that read it.
        out.push(group(
            lay.span,
            alloc::vec![1, 6],
            &[(fp_off + lay.draw_value_row, 1, f_off, 6)],
        ));
        out.push(labeled(
            "fri_draw",
            lay.span,
            alloc::vec![0, 3],
            &[(fp_off + lay.draw_value_row, 3, lay.ft_off + lay.cells.fri_index_ops[q] * l, 0)],
        ));

        // Bit k == q's fold direction at layer log_n - 2 - k == q's leaf opening's
        // path direction at level k. Level zero lives in the opened-cell column.
        let mut fsw: Vec<(usize, usize, usize, usize)> = Vec::new();
        for k in 0..lay.fbits {
            let mut cells: Vec<(usize, usize)> = alloc::vec![(fp_off + k, 0)];
            if k >= 1 {
                cells.push((m_off + k * l - 1, 8));
            }
            let fold_row = lay.log_n as usize - 2 - k;
            if fold_row < lay.n_folds {
                cells.push((f_off + fold_row, 8));
            }
            chain(&cells, &mut fsw);
        }
        out.push(group(lay.span, alloc::vec![0, 8], &fsw));
    }
}
