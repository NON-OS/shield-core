// NONOS Operating System (AGPL-3.0-or-later)

//! The region's constraints: one compress chain per opening, the path steps
//! injected in the direction the index gives, and the terminal digest left for
//! the assembly to bind.

use super::super::super::field::{Felt, Fp, Fp2};
use super::super::poseidon::{RATE, WIDTH};
use super::super::spec::{Air, AirExt};
use super::MultiMembership;
use alloc::vec::Vec;

impl MultiMembership {
    /// The transition over any field, for a recursive verifier that recomputes
    /// this region's constraints inside its own circuit.
    pub fn transition_gen<F: Felt>(&self, window: &[F], periodic: &[F]) -> Vec<F> {
        self.transition_impl(window, periodic)
    }

    fn transition_impl<F: Felt>(&self, window: &[F], periodic: &[F]) -> Vec<F> {
        let stride = self.trace_width();
        let mut state = [F::ZERO; WIDTH];
        state.copy_from_slice(&window[..WIDTH]);
        let mut rc = [F::ZERO; WIDTH];
        rc.copy_from_slice(&periodic[..WIDTH]);
        let slot_bnd = periodic[WIDTH];
        let op_bnd = periodic[WIDTH + 1];
        /*
         * The checkpoint: the last round of the last compression. Its successor
         * row holds the walked digest in the rate lanes and zero in the capacity
         * lanes, and nothing else. The row has its own selector and its own
         * rule, and the direction and sibling cells are not read on it: there
         * is no level above the last compression to inject.
         */
        let cp_bnd = if self.checkpoint_fixed() {
            periodic[self.cp_col()]
        } else {
            F::ZERO
        };
        // Direction and sibling ride the periodic columns in the per-proof form and
        // the trace in the production form. Only the per-proof form carries the next
        // opening's initial state as a periodic reset: that state is built from the
        // opening's own leaf and sibling, so in the production form it would put
        // witness into the columns a verifier key binds, and two transfers would
        // need two keys.
        let mut sib = [F::ZERO; RATE];
        let mut reset = [F::ZERO; WIDTH];
        let dir;
        if self.witness_path {
            dir = window[WIDTH];
            sib.copy_from_slice(&window[WIDTH + 1..WIDTH + 1 + RATE]);
        } else {
            dir = periodic[WIDTH + 2];
            sib.copy_from_slice(&periodic[WIDTH + 3..WIDTH + 3 + RATE]);
            reset.copy_from_slice(&periodic[WIDTH + 3 + RATE..WIDTH + 3 + RATE + WIDTH]);
        }

        let one = F::ONE;
        let mut squares: Vec<F> = Vec::new();
        let pr = if self.split {
            let sq = WIDTH + 1 + RATE;
            let mut x2 = [F::ZERO; WIDTH];
            let mut x4 = [F::ZERO; WIDTH];
            x2.copy_from_slice(&window[sq..sq + WIDTH]);
            x4.copy_from_slice(&window[sq + WIDTH..sq + 2 * WIDTH]);
            let (pr, c2, c4) = self.hasher.round_split_generic(&state, &x2, &x4, &rc);
            squares.extend(c2);
            squares.extend(c4);
            pr
        } else {
            self.hasher.round_generic(&state, &rc)
        };

        let mut out = Vec::with_capacity(WIDTH + 1 + squares.len());
        for (j, next) in window[stride..stride + WIDTH].iter().enumerate() {
            let slot_inject = if j < RATE {
                (one - dir) * pr[j] + dir * sib[j]
            } else {
                (one - dir) * sib[j - RATE] + dir * pr[j - RATE]
            };
            // At an opening boundary the production form leaves the next state to
            // the witness. It is not free: the caller binds the opened leaf to what
            // the opening authenticates and the walked root to the committed root,
            // so a chosen initial state has to be a real path to a bound leaf.
            let carry = if self.witness_path {
                op_bnd * *next
            } else {
                op_bnd * reset[j]
            };
            let checkpoint = if j < RATE { pr[j] } else { F::ZERO };
            let expected = carry
                + slot_bnd * slot_inject
                + cp_bnd * checkpoint
                + (one - op_bnd - slot_bnd - cp_bnd) * pr[j];
            out.push(*next - expected);
        }
        // The witnessed direction must be a bit, so it cannot blend the two children.
        if self.witness_path {
            out.push(dir * (one - dir));
            // Off an injection row the direction and sibling are held at zero, the
            // checkpoint row included, so no row carries a witness cell that no
            // rule reads.
            if self.checkpoint_fixed() {
                out.push((one - slot_bnd) * dir);
                for c in 0..RATE {
                    out.push((one - slot_bnd) * sib[c]);
                }
            }
        }
        out.extend(squares);
        // The bottom direction pin, on the row each opening starts. `d0` is that
        // direction as a bit, and the canonical leaf is the half it selects from
        // the initial state. The fold binds the canonical leaf, so it holds the
        // real leaf only when `d0` names the half the leaf actually occupies,
        // which the walked root already pins to the true position; the assembly
        // then binds `d0` to the recovered scalar's low bit, closing the one bit
        // the path directions left free.
        if self.pin0 {
            let op_start = periodic[WIDTH + 2];
            let d0 = window[self.dir0_col()];
            out.push(op_start * d0 * (one - d0));
            for j in 0..RATE {
                let leaf_c = window[self.leaf_col() + j];
                let selected = (one - d0) * state[j] + d0 * state[RATE + j];
                out.push(op_start * (leaf_c - selected));
            }
            /*
             * And which half of that leaf the quotient reads. A layer that
             * shares a leaf between a value and its fold partner commits both,
             * so a fixed lane is not an answer: the index's top bit decides,
             * and the assembly binds this bit to the same scalar the bottom one
             * is bound to. The selected pair is what the quotient consumes.
             */
            if self.pin_half {
                let t = window[self.half_col()];
                out.push(op_start * t * (one - t));
                for j in 0..RATE / 2 {
                    let lo = window[self.leaf_col() + j];
                    let hi = window[self.leaf_col() + RATE / 2 + j];
                    let sel = window[self.sel_col() + j];
                    out.push(op_start * (sel - ((one - t) * lo + t * hi)));
                }
            }
        }
        out
    }
}

impl AirExt for MultiMembership {
    fn transition_ext(&self, window: &[Fp2], periodic: &[Fp2]) -> Vec<Fp2> {
        self.transition_impl(window, periodic)
    }
}

impl Air for MultiMembership {
    fn log_trace_len(&self) -> u32 {
        self.work_rows().next_power_of_two().trailing_zeros()
    }

    fn rows(&self) -> usize {
        self.work_rows()
    }

    fn trace_width(&self) -> usize {
        let base = if self.witness_path {
            WIDTH + 1 + RATE
        } else {
            WIDTH
        };
        base + if self.split { 2 * WIDTH } else { 0 }
            + if self.pin0 { 1 + RATE } else { 0 }
            + if self.pin_half { 1 + RATE / 2 } else { 0 }
    }

    fn window_size(&self) -> usize {
        2
    }

    fn constraint_degree(&self) -> usize {
        if self.split {
            4
        } else {
            8
        }
    }

    fn num_transition(&self) -> usize {
        let base = if self.witness_path { WIDTH + 1 } else { WIDTH };
        let checkpoint = if self.witness_path && self.checkpoint_fixed() {
            1 + RATE
        } else {
            0
        };
        base + checkpoint
            + if self.split { 2 * WIDTH } else { 0 }
            + if self.pin0 { 1 + RATE } else { 0 }
            + if self.pin_half { 1 + RATE / 2 } else { 0 }
    }

    fn periodic_columns(&self) -> Vec<Vec<Fp>> {
        let l = self.rounds();
        let span = self.span();
        let depth = self.depth;
        let n = 1usize << self.log_trace_len();
        let count = self.openings.len();

        // Per-proof: rc[WIDTH], slot_bnd, op_bnd, dir, sib[RATE], reset[WIDTH].
        // Production: rc[WIDTH], slot_bnd, op_bnd. Dir and sib are trace, and the
        // reset is gone: it held the next opening's leaf and sibling, which is
        // witness, and witness in these columns moves the verifier key per proof.
        // Both forms end with the checkpoint selector.
        let cols_len = if self.checkpoint_fixed() {
            self.cp_col() + 1
        } else if self.witness_path {
            WIDTH + 2 + if self.pin0 { 1 } else { 0 }
        } else {
            WIDTH + 3 + RATE + WIDTH
        };
        let mut cols: Vec<Vec<Fp>> = (0..cols_len).map(|_| Vec::with_capacity(n)).collect();

        for r in 0..n {
            let rc = self.hasher.round_constant(r % l);
            for (j, col) in cols.iter_mut().take(WIDTH).enumerate() {
                col.push(rc[j]);
            }

            let opening = r / span; // which opening this row belongs to
            let within = r % span; // row inside the opening
            let at_row_boundary = within % l == l - 1;
            let is_op_boundary = within == span - 1 && opening + 1 < count;
            // A slot boundary that injects a sibling: the last round of every
            // compression but the last. The last compression's last round is the
            // checkpoint, which injects nothing.
            let is_slot_boundary = if self.checkpoint_fixed() {
                at_row_boundary && within + l < depth * l
            } else {
                at_row_boundary && within < depth * l
            };
            let is_checkpoint = at_row_boundary && within + 1 == depth * l;

            cols[WIDTH].push(if is_slot_boundary && !is_op_boundary {
                Fp::ONE
            } else {
                Fp::ZERO
            });
            cols[WIDTH + 1].push(if is_op_boundary { Fp::ONE } else { Fp::ZERO });
            if self.checkpoint_fixed() {
                let cp = self.cp_col();
                cols[cp].push(if is_checkpoint && !is_op_boundary {
                    Fp::ONE
                } else {
                    Fp::ZERO
                });
            }

            // The opening-start selector, one on the first row of each real
            // opening, where the bottom-bit and canonical-leaf constraints apply.
            if self.pin0 {
                cols[WIDTH + 2].push(if within == 0 && opening < count {
                    Fp::ONE
                } else {
                    Fp::ZERO
                });
            }

            if !self.witness_path {
                // Reset state to the next opening's initial, at an opening boundary
                // (structurally zero for a single opening).
                let reset = if is_op_boundary && opening + 1 < count {
                    self.initial_state(&self.openings[opening + 1])
                } else {
                    [Fp::ZERO; WIDTH]
                };
                // Sibling and direction for the slot injection at `within`.
                let m = (within + 1) / l;
                let (dir, sib) =
                    if is_slot_boundary && !is_op_boundary && opening < count && m < depth {
                        (
                            self.openings[opening].directions[m],
                            self.openings[opening].siblings[m],
                        )
                    } else {
                        (false, [Fp::ZERO; RATE])
                    };
                cols[WIDTH + 2].push(if dir { Fp::ONE } else { Fp::ZERO });
                for (c, s) in sib.iter().enumerate() {
                    cols[WIDTH + 3 + c].push(*s);
                }
                for (c, v) in reset.iter().enumerate() {
                    cols[WIDTH + 3 + RATE + c].push(*v);
                }
            }
        }
        cols
    }

    fn transition(&self, window: &[Fp], periodic: &[Fp]) -> Vec<Fp> {
        self.transition_impl(window, periodic)
    }

    fn boundary(&self) -> Vec<(usize, usize, Fp)> {
        let l = self.rounds();
        let span = self.span();
        let depth = self.depth;

        // Production form: nothing is pinned but what the caller names. The
        // opened leaf is bound by the assembly to the fold, and the root at the
        // checkpoint is bound to the transcript-absorbed root, so both are
        // witness rather than public.
        if self.witness_path {
            return self.bound.clone();
        }

        let mut b = Vec::with_capacity(WIDTH + self.openings.len() * RATE);
        // The first opening's whole initial state is public.
        let first = self.initial_state(&self.openings[0]);
        for (j, v) in first.iter().enumerate() {
            b.push((j, 0, *v));
        }
        // Every opening's root sits at its checkpoint.
        for (o, opening) in self.openings.iter().enumerate() {
            let row = o * span + depth * l;
            for (c, r) in opening.root.iter().enumerate() {
                b.push((c, row, *r));
            }
        }
        b
    }
}
