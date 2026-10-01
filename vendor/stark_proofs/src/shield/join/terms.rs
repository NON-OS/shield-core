// NONOS Operating System (AGPL-3.0-or-later)

use crate::crypto::stark::air::{Leg, LimbRange, ValueBalance};
use crate::crypto::stark::field::Fp;
use alloc::vec::Vec;

pub const LOG_T: u32 = 3;

pub fn limbs_of(v: u64) -> (Fp, Fp) {
    (Fp::from_u64(v & 0xFFFF_FFFF), Fp::from_u64(v >> 32))
}

/// The balance region's shape: two spent notes, two created, then the public
/// amount and the fee, then padding.
pub fn balance_shape() -> ValueBalance {
    let legs = alloc::vec![
        Leg::Input,
        Leg::Input,
        Leg::Output,
        Leg::Output,
        Leg::Output,
        Leg::Output,
        Leg::Pad,
        Leg::Pad,
    ];
    ValueBalance { log_t: LOG_T, legs }
}

pub fn balance(values: &[u64; 4], public_amount: u64, fee: u64) -> (ValueBalance, Vec<Fp>) {
    let mut terms: Vec<(Fp, Fp)> = values.iter().map(|v| limbs_of(*v)).collect();
    terms.push(limbs_of(public_amount));
    terms.push(limbs_of(fee));
    let air = balance_shape();
    let trace = air.trace(&terms);
    (air, trace)
}

/// The range region over every cell the balance region bounds, with the
/// values read from its trace.
pub fn limb_range(bal: &ValueBalance, trace: &[Fp]) -> LimbRange {
    let w = crate::crypto::stark::air::Air::trace_width(bal);
    let cells = bal.ranged();
    LimbRange {
        bits: cells.iter().map(|&(_, _, b)| b).collect(),
        values: cells.iter().map(|&(r, c, _)| trace[r * w + c].value()).collect(),
    }
}
