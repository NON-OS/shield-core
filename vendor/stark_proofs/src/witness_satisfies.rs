// NONOS Operating System (AGPL-3.0-or-later)
//! Witness satisfaction without FRI: every transition vanishes and every
//! boundary, including each grand product's z=1 closure, holds. A binding that
//! fails to close violates its boundary, so this reads the wiring directly.

use crate::crypto::stark::air::Air;
use crate::crypto::stark::field::Fp;
use alloc::vec::Vec;

pub(crate) fn satisfies(air: &(impl Air + Sync), witness: &[Fp]) -> bool {
    let w = air.trace_width();
    let ws = air.window_size();
    let total = 1usize << air.log_trace_len();
    let periodic = air.periodic_columns();
    // Rows are independent, so they check in parallel chunks; at a deep trace
    // the serial walk was most of an hour per gate. A violation anywhere
    // fails the whole thing, which is all a boolean needs to know.
    let rows = total - (ws - 1);
    const CHUNK: usize = 4096;
    let chunks = rows.div_ceil(CHUNK);
    let ok = crate::crypto::stark::par::map_index(chunks, |b| {
        let (lo, hi) = (b * CHUNK, ((b + 1) * CHUNK).min(rows));
        let mut window = Vec::with_capacity(ws * w);
        let mut per = Vec::with_capacity(periodic.len());
        for r in lo..hi {
            window.clear();
            for k in 0..ws {
                window.extend_from_slice(&witness[(r + k) * w..(r + k + 1) * w]);
            }
            per.clear();
            per.extend(periodic.iter().map(|c| c[r]));
            if air.transition(&window, &per).iter().any(|v| *v != Fp::ZERO) {
                return false;
            }
        }
        true
    });
    if ok.iter().any(|v| !v) {
        return false;
    }
    for (col, row, val) in air.boundary() {
        if witness[row * w + col] != val {
            return false;
        }
    }
    true
}

/// The first `limit` violations as (row, lane), boundaries reported as lane
/// `num_transition + column`: what a gate prints when a witness does not
/// satisfy, so the region and the constraint are named rather than guessed.
/// Rows check in parallel chunks, as `satisfies` does: the serial walk was
/// three hours on the wrap at every query.
#[cfg(test)]
pub(crate) fn violations(air: &(impl Air + Sync), witness: &[Fp], limit: usize) -> Vec<(usize, usize)> {
    let w = air.trace_width();
    let ws = air.window_size();
    let total = 1usize << air.log_trace_len();
    let periodic = air.periodic_columns();
    let rows = total - (ws - 1);
    let nt = air.num_transition();
    const CHUNK: usize = 4096;
    let chunks = rows.div_ceil(CHUNK);
    let found: Vec<Vec<(usize, usize)>> = crate::crypto::stark::par::map_index(chunks, |b| {
        let (lo, hi) = (b * CHUNK, ((b + 1) * CHUNK).min(rows));
        let mut out = Vec::new();
        let mut window = Vec::with_capacity(ws * w);
        let mut per = Vec::with_capacity(periodic.len());
        for r in lo..hi {
            window.clear();
            for k in 0..ws {
                window.extend_from_slice(&witness[(r + k) * w..(r + k + 1) * w]);
            }
            per.clear();
            per.extend(periodic.iter().map(|c| c[r]));
            for (lane, v) in air.transition(&window, &per).iter().enumerate() {
                if *v != Fp::ZERO {
                    out.push((r, lane));
                    if out.len() >= limit {
                        return out;
                    }
                }
            }
        }
        out
    });
    let mut out: Vec<(usize, usize)> = found.into_iter().flatten().collect();
    for (col, row, val) in air.boundary() {
        if witness[row * w + col] != val {
            out.push((row, nt + col));
        }
    }
    out.truncate(limit);
    out
}
