// NONOS Operating System (AGPL-3.0-or-later)

//! The witness this region proves: one compress chain per opening, the path
//! injected in the direction the index gives, and the pinned cells each opening
//! writes on the row it starts.

use super::super::super::field::Fp;
use super::super::poseidon::{RATE, WIDTH};
use super::super::spec::Air;
use super::MultiMembership;
use alloc::vec::Vec;

impl MultiMembership {
    /// The witness trace for this batch: run each opening's Merkle path, reset to
    /// the next opening's leaf at each opening boundary, and let padding rows run
    /// the permutation. The single source of truth for the layout, so callers
    /// prove against exactly what the constraints check.
    pub fn trace(&self) -> Vec<Fp> {
        let l = self.rounds();
        let span = self.span();
        let depth = self.depth;
        let count = self.openings.len();
        let n = 1usize << self.log_trace_len();
        let w = self.trace_width();

        let mut trace = alloc::vec![Fp::ZERO; n * w];
        let sq_base = WIDTH + 1 + RATE;
        let mut state = self.initial_state(&self.openings[0]);
        for r in 0..n {
            trace[r * w..r * w + WIDTH].copy_from_slice(&state);
            if self.split {
                for j in 0..WIDTH {
                    let x2 = state[j] * state[j];
                    trace[r * w + sq_base + j] = x2;
                    trace[r * w + sq_base + WIDTH + j] = x2 * x2;
                }
            }
            let pr = self.hasher.round_with_rc(&state, &self.hasher.round_constant(r % l));
            let opening = r / span;
            let within = r % span;
            let at_row_bnd = within % l == l - 1;
            let is_op_bnd = within == span - 1 && opening + 1 < count;
            let is_slot_bnd = at_row_bnd && within < depth * l && !is_op_bnd;
            // In the production form the compression's direction and sibling ride the
            // trace, at exactly the rows the transition reads them.
            if self.witness_path {
                let m = (within + 1) / l;
                let (dir, sib) = if is_slot_bnd && opening < count && m < depth {
                    (self.openings[opening].directions[m], self.openings[opening].siblings[m])
                } else {
                    (false, [Fp::ZERO; RATE])
                };
                trace[r * w + WIDTH] = if dir { Fp::ONE } else { Fp::ZERO };
                for (c, s) in sib.iter().enumerate() {
                    trace[r * w + WIDTH + 1 + c] = *s;
                }
            }
            // The bottom direction and the canonical leaf, written on the row each
            // opening starts, where the select constraint reads the two halves.
            if self.pin0 && within == 0 && opening < count {
                let o = &self.openings[opening];
                trace[r * w + self.dir0_col()] = if o.directions[0] { Fp::ONE } else { Fp::ZERO };
                for (j, v) in o.leaf.iter().enumerate() {
                    trace[r * w + self.leaf_col() + j] = *v;
                }
                /*
                 * The half the quotient reads. The leaf holds two extension
                 * values and the index's top bit says which, so the top of the
                 * position is written here and the selected pair beside it. The
                 * assembly binds the bit to the same scalar the bottom bit is
                 * bound to; unbound it is the prover naming which committed
                 * value the quotient consumes.
                 */
                if self.pin_half {
                    let top = self.half_of(opening);
                    trace[r * w + self.half_col()] = if top { Fp::ONE } else { Fp::ZERO };
                    let lo = if top { RATE / 2 } else { 0 };
                    for j in 0..RATE / 2 {
                        trace[r * w + self.sel_col() + j] = o.leaf[lo + j];
                    }
                }
            }
            if is_op_bnd {
                state = self.initial_state(&self.openings[opening + 1]);
            } else if is_slot_bnd {
                let m = (within + 1) / l;
                let mut digest = [Fp::ZERO; RATE];
                digest.copy_from_slice(&pr[..RATE]);
                if opening < count && m < depth {
                    let o = &self.openings[opening];
                    state = inject(digest, o.siblings[m], o.directions[m]);
                } else {
                    state = inject(digest, [Fp::ZERO; RATE], false);
                }
            } else {
                state = pr;
            }
        }
        trace
    }
}

pub(super) fn inject(node: [Fp; RATE], sibling: [Fp; RATE], right: bool) -> [Fp; WIDTH] {
    let mut state = [Fp::ZERO; WIDTH];
    if !right {
        state[..RATE].copy_from_slice(&node);
        state[RATE..].copy_from_slice(&sibling);
    } else {
        state[..RATE].copy_from_slice(&sibling);
        state[RATE..].copy_from_slice(&node);
    }
    state
}
