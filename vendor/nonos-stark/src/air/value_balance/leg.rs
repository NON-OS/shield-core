// NONOS Operating System (AGPL-3.0-or-later)

//! Which side of the balance a row sits on: an input adds its value, an output subtracts it,
//! a pad row contributes nothing. The leg is public structure carried on a periodic column
//! rather than witness, which is the fact the region's soundness rests on: a prover chooses
//! the values on the rows but not whether a row counts as an input or an output.

use super::super::super::field::Fp;

/// Which side of the balance a row sits on. Batch layout is public structure, not
/// witness, so this rides a periodic column: a prover cannot choose which row is
/// an input.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Leg {
    Input,
    Output,
    Pad,
}

impl Leg {
    pub(super) fn sign(self) -> Fp {
        match self {
            Leg::Input => Fp::ONE,
            Leg::Output => Fp::ZERO - Fp::ONE,
            Leg::Pad => Fp::ZERO,
        }
    }
}
