// NONOS Operating System (AGPL-3.0-or-later)

//! The grinding hash on arm64 with the SHA3 instructions, two nonces at once.
//!
//! A phone's cores have the ARMv8.2 SHA3 extension (A16, recent Snapdragon
//! and Tensor). Each NEON register holds the same lane of two Keccak states,
//! so one permutation serves two nonces, and the four SHA3 instructions do
//! most of a round's work directly: EOR3 for the column parities, RAX1 for
//! theta's rotate and xor, XAR to fold theta into rho, BCAX for chi. Only the
//! grind uses this; it is 2^28 hashes of one fixed block, where the other
//! Keccak uses in the prover are not.
//!
//! `pow_lanes2` is `pow_lane` for two nonces, bit for bit. `sha3_available`
//! says whether the running core has the instructions; the caller falls back
//! to `pow_lane` when it does not.

use super::constants::ROUND_CONSTANTS;
use core::arch::aarch64::*;

extern crate std;

/// Whether this core has the SHA3 instructions.
pub(crate) fn sha3_available() -> bool {
    std::arch::is_aarch64_feature_detected!("sha3")
}

/// `rotl(a ^ d, r)`, as XAR's rotate right by `64 - r`.
macro_rules! xr {
    ($a:expr, $d:expr, $r:literal) => {
        vxarq_u64::<{ (64 - $r) % 64 }>($a, $d)
    };
}

/// Keccak-f[1600] on two states at once, lane `i` of both in `s[i]`.
#[target_feature(enable = "sha3")]
unsafe fn keccak_f_x2(s: &mut [uint64x2_t; 25]) {
    for &rc in ROUND_CONSTANTS.iter().take(24) {
        // theta
        let c0 = veor3q_u64(veor3q_u64(s[0], s[5], s[10]), s[15], s[20]);
        let c1 = veor3q_u64(veor3q_u64(s[1], s[6], s[11]), s[16], s[21]);
        let c2 = veor3q_u64(veor3q_u64(s[2], s[7], s[12]), s[17], s[22]);
        let c3 = veor3q_u64(veor3q_u64(s[3], s[8], s[13]), s[18], s[23]);
        let c4 = veor3q_u64(veor3q_u64(s[4], s[9], s[14]), s[19], s[24]);
        let d0 = vrax1q_u64(c4, c1);
        let d1 = vrax1q_u64(c0, c2);
        let d2 = vrax1q_u64(c1, c3);
        let d3 = vrax1q_u64(c2, c4);
        let d4 = vrax1q_u64(c3, c0);

        // theta applied inside rho, then pi: b[pi(i)] = rotl(a[i] ^ d, r_i)
        let b0 = veorq_u64(s[0], d0);
        let b10 = xr!(s[1], d1, 1);
        let b20 = xr!(s[2], d2, 62);
        let b5 = xr!(s[3], d3, 28);
        let b15 = xr!(s[4], d4, 27);
        let b16 = xr!(s[5], d0, 36);
        let b1 = xr!(s[6], d1, 44);
        let b11 = xr!(s[7], d2, 6);
        let b21 = xr!(s[8], d3, 55);
        let b6 = xr!(s[9], d4, 20);
        let b7 = xr!(s[10], d0, 3);
        let b17 = xr!(s[11], d1, 10);
        let b2 = xr!(s[12], d2, 43);
        let b12 = xr!(s[13], d3, 25);
        let b22 = xr!(s[14], d4, 39);
        let b23 = xr!(s[15], d0, 41);
        let b8 = xr!(s[16], d1, 45);
        let b18 = xr!(s[17], d2, 15);
        let b3 = xr!(s[18], d3, 21);
        let b13 = xr!(s[19], d4, 8);
        let b14 = xr!(s[20], d0, 18);
        let b24 = xr!(s[21], d1, 2);
        let b9 = xr!(s[22], d2, 61);
        let b19 = xr!(s[23], d3, 56);
        let b4 = xr!(s[24], d4, 14);

        // chi: a = b ^ (!b1 & b2), which is BCAX(b, b2, b1)
        let rows = [[b0, b1, b2, b3, b4], [b5, b6, b7, b8, b9], [b10, b11, b12, b13, b14], [b15, b16, b17, b18, b19], [b20, b21, b22, b23, b24]];
        for (y, r) in rows.iter().enumerate() {
            for x in 0..5 {
                s[5 * y + x] = vbcaxq_u64(r[x], r[(x + 2) % 5], r[(x + 1) % 5]);
            }
        }

        // iota
        s[0] = veorq_u64(s[0], vdupq_n_u64(rc));
    }
}

/// `pow_lane(template, n0)` and `pow_lane(template, n1)` in one permutation.
/// The caller has checked `sha3_available`.
pub(crate) fn pow_lanes2(template: &[u64; 25], n0: u64, n1: u64) -> (u64, u64) {
    // SAFETY: plain NEON loads and stores on arrays of the right length; the
    // caller has checked that the core has the SHA3 instructions.
    unsafe {
        let mut s = [vdupq_n_u64(0); 25];
        for (i, lane) in s.iter_mut().enumerate() {
            *lane = vdupq_n_u64(template[i]);
        }
        let l4 = [template[4] | (n0 << 8), template[4] | (n1 << 8)];
        let l5 = [template[5] | (n0 >> 56), template[5] | (n1 >> 56)];
        s[4] = vld1q_u64(l4.as_ptr());
        s[5] = vld1q_u64(l5.as_ptr());
        keccak_f_x2(&mut s);
        let mut out = [0u64; 2];
        vst1q_u64(out.as_mut_ptr(), s[0]);
        (out[0], out[1])
    }
}

#[cfg(test)]
mod tests {
    use super::super::keccak::{pow_lane, pow_template};
    use super::*;

    /// The two-way permutation is the portable one, lane for lane, across
    /// tags, states and nonces that cross the lane boundary.
    #[test]
    fn two_nonces_at_once_is_pow_lane_twice() {
        if !sha3_available() {
            std::eprintln!("no SHA3 instructions on this core; nothing to compare");
            return;
        }
        let mut seed = 0x0123_4567_89ab_cdefu64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for tag in [0x05u8, 0x06] {
            for _ in 0..200 {
                let mut state = [0u8; 32];
                for b in state.iter_mut() {
                    *b = next() as u8;
                }
                let t = pow_template(tag, &state);
                for (a, b) in [(0u64, 1u64), (u64::MAX, 1 << 56), (next(), next())] {
                    assert_eq!(pow_lanes2(&t, a, b), (pow_lane(&t, a), pow_lane(&t, b)), "nonces {a:#x} {b:#x}");
                }
            }
        }
    }
}
