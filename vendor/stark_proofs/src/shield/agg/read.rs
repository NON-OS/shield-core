// NONOS Operating System (AGPL-3.0-or-later)

use super::effect::Effect;
use crate::crypto::stark::air::{INJECT, RATE};
use crate::crypto::stark::field::Fp;
use crate::shield::join::publics::{NF0, NF1, OUT_CM0, OUT_CM1};

/// Where inner public word `i` sits in the assembled trace.
///
/// The transcript absorbs the publics before it absorbs anything else, four
/// to a block, so word `i` is lane `i mod 4` of block `i / 4`, and a block is
/// `l` rows. The value rides an injection column rather than a state lane:
/// the sponge adds it at the block's first row and a periodic selector pins
/// the column to
/// zero on every other row, so this is the cell the proof actually consumed. A
/// state lane at the same row holds the sponge mid flight, which moves with the
/// publics without being them, and reading one would decouple the effect from
/// the proof while still looking like it tracked.
pub fn absorbed_at(l: usize, i: usize) -> (usize, usize) {
    ((i / RATE) * l, INJECT + i % RATE)
}

fn word(trace: &[Fp], width: usize, l: usize, i: usize) -> Fp {
    let (row, col) = absorbed_at(l, i);
    trace[row * width + col]
}

fn digest(trace: &[Fp], width: usize, l: usize, at: usize) -> [Fp; RATE] {
    let mut d = [Fp::ZERO; RATE];
    for (c, lane) in d.iter_mut().enumerate() {
        *lane = word(trace, width, l, at + c);
    }
    d
}

/// The effect a verified inner proof published, read from the cells its own
/// transcript absorbed.
///
/// This is the seam. Verifying the child proves its publics; reading them here
/// is what carries that binding into the transition the node composes. Take the
/// effect as a witness instead and a node verifies one proof and composes
/// another's move, with every proof in the tree still verifying. `base` is where
/// the intent's words begin, since a node's inner proof carries more than one.
pub fn read_effect(trace: &[Fp], width: usize, l: usize, base: usize) -> Effect {
    Effect {
        nullifiers: [
            digest(trace, width, l, base + NF0),
            digest(trace, width, l, base + NF1),
        ],
        outputs: [
            digest(trace, width, l, base + OUT_CM0),
            digest(trace, width, l, base + OUT_CM1),
        ],
    }
}
