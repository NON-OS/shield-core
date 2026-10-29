// NONOS Operating System (AGPL-3.0-or-later)

//! The grinding hash in a threaded browser build, two nonces at once.
//!
//! A wasm SIMD register holds the same lane of two Keccak states, so one
//! permutation serves two nonces. In V8 this hashes about 2.3 times as many
//! nonces a second as `pow_lane` does. Only this function is built with
//! `simd128`: the whole module built with it ran the rest of the prover
//! slower. The threaded build already needs a browser from 2023 or later, and
//! every one of those runs wasm SIMD, so a module that loads at all has it.
//!
//! `pow_lanes2` is `pow_lane` for two nonces, bit for bit.

use super::constants::ROUND_CONSTANTS;
use core::arch::wasm32::*;

/// Whether this build hashes two nonces at once. A module that loaded has SIMD.
pub(crate) fn simd_available() -> bool {
    true
}

/// `x` rotated left by `r`, which wasm SIMD has only as two shifts and an or.
#[inline(always)]
fn rotl(x: v128, r: u32) -> v128 {
    v128_or(i64x2_shl(x, r), u64x2_shr(x, 64 - r))
}

/// Keccak-f[1600] on two states at once, lane `i` of both in `s[i]`. It and
/// `rotl` are inlined into `lanes2`, the one function built with `simd128`: a
/// SIMD operation outside it, in a closure too, is a call per instruction.
#[inline(always)]
fn keccak_f_x2(s: &mut [v128; 25]) {
    for &rc in ROUND_CONSTANTS.iter().take(24) {
        // theta
        let c0 = v128_xor(v128_xor(v128_xor(s[0], s[5]), v128_xor(s[10], s[15])), s[20]);
        let c1 = v128_xor(v128_xor(v128_xor(s[1], s[6]), v128_xor(s[11], s[16])), s[21]);
        let c2 = v128_xor(v128_xor(v128_xor(s[2], s[7]), v128_xor(s[12], s[17])), s[22]);
        let c3 = v128_xor(v128_xor(v128_xor(s[3], s[8]), v128_xor(s[13], s[18])), s[23]);
        let c4 = v128_xor(v128_xor(v128_xor(s[4], s[9]), v128_xor(s[14], s[19])), s[24]);
        let d = [
            v128_xor(c4, rotl(c1, 1)),
            v128_xor(c0, rotl(c2, 1)),
            v128_xor(c1, rotl(c3, 1)),
            v128_xor(c2, rotl(c4, 1)),
            v128_xor(c3, rotl(c0, 1)),
        ];
        // theta applied inside rho, then pi, as in `keccak_f`: b[pi(i)] = rotl(a[i] ^ d, r_i)
        let b = [
            v128_xor(s[0], d[0]),
            rotl(v128_xor(s[6], d[1]), 44),
            rotl(v128_xor(s[12], d[2]), 43),
            rotl(v128_xor(s[18], d[3]), 21),
            rotl(v128_xor(s[24], d[4]), 14),
            rotl(v128_xor(s[3], d[3]), 28),
            rotl(v128_xor(s[9], d[4]), 20),
            rotl(v128_xor(s[10], d[0]), 3),
            rotl(v128_xor(s[16], d[1]), 45),
            rotl(v128_xor(s[22], d[2]), 61),
            rotl(v128_xor(s[1], d[1]), 1),
            rotl(v128_xor(s[7], d[2]), 6),
            rotl(v128_xor(s[13], d[3]), 25),
            rotl(v128_xor(s[19], d[4]), 8),
            rotl(v128_xor(s[20], d[0]), 18),
            rotl(v128_xor(s[4], d[4]), 27),
            rotl(v128_xor(s[5], d[0]), 36),
            rotl(v128_xor(s[11], d[1]), 10),
            rotl(v128_xor(s[17], d[2]), 15),
            rotl(v128_xor(s[23], d[3]), 56),
            rotl(v128_xor(s[2], d[2]), 62),
            rotl(v128_xor(s[8], d[3]), 55),
            rotl(v128_xor(s[14], d[4]), 39),
            rotl(v128_xor(s[15], d[0]), 41),
            rotl(v128_xor(s[21], d[1]), 2),
        ];

        // chi: b ^ (!b1 & b2), which is andnot(b2, b1)
        for y in 0..5 {
            let r = 5 * y;
            s[r] = v128_xor(b[r], v128_andnot(b[r + 2], b[r + 1]));
            s[r + 1] = v128_xor(b[r + 1], v128_andnot(b[r + 3], b[r + 2]));
            s[r + 2] = v128_xor(b[r + 2], v128_andnot(b[r + 4], b[r + 3]));
            s[r + 3] = v128_xor(b[r + 3], v128_andnot(b[r], b[r + 4]));
            s[r + 4] = v128_xor(b[r + 4], v128_andnot(b[r + 1], b[r]));
        }

        // iota
        s[0] = v128_xor(s[0], u64x2_splat(rc));
    }
}

/// `pow_lane(template, n0)` and `pow_lane(template, n1)` in one permutation.
pub(crate) fn pow_lanes2(template: &[u64; 25], n0: u64, n1: u64) -> (u64, u64) {
    // The module was validated with its SIMD instructions in it, so the engine
    // running it has wasm SIMD.
    lanes2(template, n0, n1)
}

#[target_feature(enable = "simd128")]
fn lanes2(template: &[u64; 25], n0: u64, n1: u64) -> (u64, u64) {
    let mut s = [u64x2_splat(0); 25];
    for i in 0..25 {
        s[i] = u64x2_splat(template[i]);
    }
    s[4] = u64x2(template[4] | (n0 << 8), template[4] | (n1 << 8));
    s[5] = u64x2(template[5] | (n0 >> 56), template[5] | (n1 >> 56));
    keccak_f_x2(&mut s);
    (u64x2_extract_lane::<0>(s[0]), u64x2_extract_lane::<1>(s[0]))
}

/// The keccak256 rate in bytes.
const RATE: usize = 136;

/// keccak256 of two messages of the same length at once: one permutation a
/// block serves both. The Merkle trees hash leaves and nodes this way, two by
/// two, and each digest is the one `Keccak` gives for its message alone.
pub(crate) struct Keccak2 {
    state: [[u64; 2]; 25],
    buf: [[u8; RATE]; 2],
    n: usize,
}

impl Keccak2 {
    pub(crate) fn new() -> Keccak2 {
        Keccak2 { state: [[0; 2]; 25], buf: [[0; RATE]; 2], n: 0 }
    }

    /// Absorb `a` into the first message and `b`, as long, into the second.
    pub(crate) fn update(&mut self, a: &[u8], b: &[u8]) {
        debug_assert_eq!(a.len(), b.len());
        let mut at = 0;
        while at < a.len() {
            let take = core::cmp::min(RATE - self.n, a.len() - at);
            self.buf[0][self.n..self.n + take].copy_from_slice(&a[at..at + take]);
            self.buf[1][self.n..self.n + take].copy_from_slice(&b[at..at + take]);
            self.n += take;
            at += take;
            if self.n == RATE {
                absorb(&mut self.state, &self.buf);
                self.n = 0;
            }
        }
    }

    /// Both digests, padded as `Keccak::new(512, 32, 0x01)` pads.
    pub(crate) fn finalize32(mut self) -> ([u8; 32], [u8; 32]) {
        for buf in self.buf.iter_mut() {
            buf[self.n] = 0x01;
            buf[self.n + 1..].fill(0);
            buf[RATE - 1] |= 0x80;
        }
        absorb(&mut self.state, &self.buf);
        let mut out = [[0u8; 32]; 2];
        for (k, d) in out.iter_mut().enumerate() {
            for lane in 0..4 {
                d[8 * lane..8 * lane + 8].copy_from_slice(&self.state[lane][k].to_le_bytes());
            }
        }
        (out[0], out[1])
    }
}

/// One full block of each message into the two states, then the permutation.
fn absorb(state: &mut [[u64; 2]; 25], buf: &[[u8; RATE]; 2]) {
    // The module was validated with its SIMD instructions in it.
    absorb_simd(state, buf)
}

#[target_feature(enable = "simd128")]
fn absorb_simd(state: &mut [[u64; 2]; 25], buf: &[[u8; RATE]; 2]) {
    let mut s = [u64x2_splat(0); 25];
    for i in 0..25 {
        let [mut x, mut y] = state[i];
        if i < RATE / 8 {
            let mut lane = [0u8; 8];
            lane.copy_from_slice(&buf[0][8 * i..8 * i + 8]);
            x ^= u64::from_le_bytes(lane);
            lane.copy_from_slice(&buf[1][8 * i..8 * i + 8]);
            y ^= u64::from_le_bytes(lane);
        }
        s[i] = u64x2(x, y);
    }
    keccak_f_x2(&mut s);
    for i in 0..25 {
        state[i] = [u64x2_extract_lane::<0>(s[i]), u64x2_extract_lane::<1>(s[i])];
    }
}
