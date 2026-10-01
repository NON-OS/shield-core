// NONOS Operating System (AGPL-3.0-or-later)

use super::bind::Layout;
use super::publics::{
    ASSET_ID, ASSOC_ROOT, FEE, INPUT_SUM_HI, INPUT_SUM_LO, NF0, NF1, NOTE_ROOT, OUT_CM0, OUT_CM1,
    PUBLIC_AMOUNT,
};
use crate::crypto::stark::air::{LiveGate, RATE};
use crate::shield::key::dead_lane_cell;
use crate::shield::note::{cm_row, public_row, POOL_LOG_ROUNDS};
use crate::shield::wire_class::{pair, tie, Class};
use alloc::vec::Vec;

/// Every word is tied to the cell that computes it. A tamper test alone would
/// only show a word is constrained to something, not to the right something.
pub fn public_classes(l: &Layout, pub_off: usize) -> Vec<Class> {
    let mut g = Vec::new();
    let rounds = 1usize << POOL_LOG_ROUNDS;
    let word = |i: usize| pub_off + i;

    /*
     * Membership, through the live gate rather than as a bare equality.
     *
     * An unbound walk is honest arithmetic that ends wherever its siblings take
     * it, so every input's terminal has to be reached by something. It used to
     * be reached by a class straight onto the published word, which is an
     * equality and cannot be conditional, and a payment needs it conditional:
     * a wallet holding one note pays with a dummy beside it and has nothing to
     * open for that leg.
     *
     * So each input's terminal is tied into its own gate, the published word is
     * tied in beside it, and the gate multiplies the difference by the live
     * bit. One class per cell, all disjoint, because two classes over one cell
     * are one binding.
     */
    for (i, &m) in l.member.iter().enumerate() {
        let gate = l.live[i];
        for c in 0..RATE {
            g.push(pair(
                m + l.depth * rounds,
                c,
                gate,
                LiveGate::walked_note_col(c),
            ));
        }
        // The bit costs value, so the value the gate holds has to be the value
        // the balance row summed.
        g.push(pair(l.balance + i, 1, gate, LiveGate::value_col(0)));
        g.push(pair(l.balance + i, 2, gate, LiveGate::value_col(1)));
    }

    // The published word and every gate's copy of it, one class per lane. One
    // class per gate would be one binding, the last, and the other gate would
    // hold a root nothing reaches.
    for c in 0..RATE {
        let mut cells = alloc::vec![(word(NOTE_ROOT + c), 0)];
        cells.extend(
            l.live
                .iter()
                .map(|&gate| (gate, LiveGate::note_root_col(c))),
        );
        g.push(tie(&cells));
    }

    /*
     * Each retired nullifier is the one its key hierarchy produced, and the
     * lane of the word it hashed that says live or dead is the gate's.
     *
     * Every other lane of that word is pinned by the key region to a constant
     * or to the recovered position. This one cannot be: it is the one thing in
     * the key hierarchy that depends on liveness, and only the gate knows that.
     * Left unbound it is a free cell, and a free cell there lets a dummy pick
     * where its nullifier lands, which the pool burns without being able to
     * tell it from a note's.
     */
    for (i, &base) in l.key.iter().enumerate() {
        let nf = base + 3 * l.key_span[i] + rounds;
        let at = if i == 0 { NF0 } else { NF1 };
        for c in 0..RATE {
            g.push(pair(word(at + c), 0, nf, c));
        }
        let (row, col) = dead_lane_cell(l.key_span[i]);
        g.push(pair(base + row, col, l.live[i], LiveGate::dead_col()));
    }

    // Each created commitment is the one the output note committed to.
    for (i, at) in [OUT_CM0, OUT_CM1].into_iter().enumerate() {
        let cm = cm_row(l.note[2 + i], l.span_op);
        for c in 0..RATE {
            g.push(pair(word(at + c), 0, cm, c));
        }
    }

    // The public legs are the recomposed values the balance summed, not numbers
    // restated beside it.
    g.push(pair(word(PUBLIC_AMOUNT), 0, l.balance + 4, 3));
    g.push(pair(word(FEE), 0, l.balance + 5, 3));
    g.push(pair(word(ASSET_ID), 0, public_row(l.note[0], l.span_op), 2));

    // The claim's two sums are the balance region's running sums after the
    // two input legs, row 2: the low sum in column 0, the high in column 4.
    if cfg!(feature = "claim") {
        g.push(pair(word(INPUT_SUM_LO), 0, l.balance + 2, 0));
        g.push(pair(word(INPUT_SUM_HI), 0, l.balance + 2, 4));
    }

    // The association set, through the same gate and for the same reason.
    for (i, &a) in l.assoc.iter().enumerate() {
        let gate = l.live[i];
        for c in 0..RATE {
            g.push(pair(
                a + l.depth * rounds,
                c,
                gate,
                LiveGate::walked_assoc_col(c),
            ));
        }
    }
    for c in 0..RATE {
        let mut cells = alloc::vec![(word(ASSOC_ROOT + c), 0)];
        cells.extend(
            l.live
                .iter()
                .map(|&gate| (gate, LiveGate::assoc_root_col(c))),
        );
        g.push(tie(&cells));
    }
    g
}
