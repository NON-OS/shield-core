// NONOS Operating System (AGPL-3.0-or-later)
//! The two index regions for one query: the consistency draw walked to
//! `shift * omega^p_k`, the x the DEEP check divides by, and the FRI draw
//! walked to `shift * omega^i_k`, the layer-zero point the fold chain descends
//! from. Both decompose the one element FRI's transcript squeezed for query
//! k, after its nonce: the consistency check runs at FRI's position, all
//! `log n` bits of it, and the fold at its low `log n - 1`. The assembly
//! binds each recovered element back to that squeeze cell and the bits to
//! the paths. The first FRI draw of a proof read the grinding word,
//! so its top `grind` bits are pinned to zero: the proof of work, checked.

use super::tamper::Tamper;
use crate::crypto::stark::air::IndexDraw;
use crate::crypto::stark::field::Fp;
use crate::crypto::stark::fri::root_of_unity;
use alloc::vec::Vec;

pub struct PointSide {
    pub ip: IndexDraw,
    pub itrace: Vec<Fp>,
    pub pbits: usize,
    pub fp: IndexDraw,
    pub fptrace: Vec<Fp>,
    pub fbits: usize,
}

/// The regions for query `k`: `cons_value` and `fri_value` are both the
/// element FRI's draw for query `k` read; they are two parameters so a tamper
/// can bend one side alone.
pub fn point_regions_k(
    cons_value: u64,
    fri_value: u64,
    log_n: u32,
    query: usize,
    grind: u32,
    tamper: Tamper,
) -> PointSide {
    let bo = root_of_unity(log_n);
    let shift = Fp::from_u64(7);
    let pbits = log_n as usize;
    // A bit above every index bit and below the grind's: bends the recovered
    // element and nothing the block sees.
    let above = 1u64 << 40;
    let cons_value = match tamper {
        Tamper::ForeignConsistencyIndex => cons_value ^ 1,
        Tamper::DrawOffTranscript => cons_value ^ above,
        _ => cons_value,
    };
    let fri_value = match tamper {
        Tamper::FriDrawOffTranscript => fri_value ^ above,
        _ => fri_value,
    };
    let ip = IndexDraw::new(bo, shift, pbits, cons_value, 0);
    let itrace = ip.trace();
    let fbits = (log_n - 1) as usize;
    let zero_top = if query == 0 { grind as usize } else { 0 };
    let fp = IndexDraw::new(bo, shift, fbits, fri_value, zero_top);
    let fptrace = fp.trace();
    PointSide {
        ip,
        itrace,
        pbits,
        fp,
        fptrace,
        fbits,
    }
}
