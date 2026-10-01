//! The field multiply in aarch64 assembly, opt in until a device measurement beats the portable
//! fold, since hand written assembly on a trust path is permanent audit surface.

use super::consts::{EPSILON, P};

/// The portable fold, with `csel` keeping both corrections branchless where a compiler may emit
/// a mispredicting branch. Inputs must be canonical, and the result is canonical.
#[inline]
pub fn mul(a: u64, b: u64) -> u64 {
    let out: u64;
    // SAFETY: registers only, with no memory, division or floating point, so it cannot trap and
    // `pure, nomem, nostack` hold.
    unsafe {
        core::arch::asm!(
            "mul   {lo}, {a}, {b}",
            "umulh {hi}, {a}, {b}",
            "lsr   {hh}, {hi}, #32",
            "and   {hl}, {hi}, #0xffffffff",
            "subs  {t0}, {lo}, {hh}",
            "sub   {t1}, {t0}, {eps}",
            "csel  {t0}, {t1}, {t0}, cc",
            "mul   {t1}, {hl}, {eps}",
            "adds  {t0}, {t0}, {t1}",
            "add   {t1}, {t0}, {eps}",
            "csel  {t0}, {t1}, {t0}, cs",
            "subs  {t1}, {t0}, {p}",
            "csel  {out}, {t1}, {t0}, cs",
            a = in(reg) a,
            b = in(reg) b,
            eps = in(reg) EPSILON,
            p = in(reg) P,
            lo = out(reg) _,
            hi = out(reg) _,
            hh = out(reg) _,
            hl = out(reg) _,
            t0 = out(reg) _,
            t1 = out(reg) _,
            out = out(reg) out,
            options(pure, nomem, nostack),
        );
    }
    out
}
