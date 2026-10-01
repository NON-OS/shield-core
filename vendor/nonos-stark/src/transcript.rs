// NONOS Operating System (AGPL-3.0-or-later)

//! A Fiat-Shamir transcript over Keccak256 (the EVM-native hash, so the Each absorb folds its input into a
//! running 32-byte state under a domain tag; each challenge folds a tag in and
//! reads the fresh state. A prover and verifier that absorb the same sequence
//! draw the same challenges, which is what turns the interactive FRI protocol
//! into a non-interactive one, sound in the random-oracle model.

use super::field::{Fp, Fp2};
use crate::hash::{keccak256, pow_lane, pow_template};
use crate::merkle::DIGEST_BYTES;
use alloc::vec::Vec;

#[derive(Clone)]
pub struct Transcript {
    state: [u8; 32],
}

impl Transcript {
    pub fn new(label: &[u8]) -> Transcript {
        let t = Transcript {
            state: keccak256(label),
        };
        #[cfg(feature = "kat")]
        kat::record(kat::NEW, label, &t.state);
        t
    }

    fn mix(&mut self, tag: u8, data: &[u8]) {
        let mut buf = Vec::with_capacity(1 + 32 + data.len());
        buf.push(tag);
        buf.extend_from_slice(&self.state);
        buf.extend_from_slice(data);
        self.state = keccak256(&buf);
        #[cfg(feature = "kat")]
        kat::record(tag, data, &self.state);
    }

    /// Absorb a commitment root: its kept bytes, which are the bytes a
    /// verifier reads off the wire.
    pub fn absorb_digest(&mut self, digest: &[u8; 32]) {
        self.mix(0x01, &digest[..DIGEST_BYTES]);
    }

    /// Absorb a field element.
    pub fn absorb_fp(&mut self, value: Fp) {
        self.mix(0x02, &value.value().to_le_bytes());
    }

    /// Absorb a vector of field elements. On the v1 transcript this is one
    /// absorb per element, exactly as the loops it replaces. On v2 it is one
    /// Keccak over the whole vector, each element as eight little-endian
    /// bytes; every vector's length is fixed by the parameters, so the length
    /// is not absorbed (docs/17).
    pub fn absorb_fp_vec(&mut self, values: &[Fp]) {
        #[cfg(feature = "v2")]
        {
            let mut data = Vec::with_capacity(8 * values.len());
            for v in values {
                data.extend_from_slice(&v.value().to_le_bytes());
            }
            self.mix(0x02, &data);
        }
        #[cfg(not(feature = "v2"))]
        for v in values {
            self.absorb_fp(*v);
        }
    }

    /// Absorb a vector of extension elements, each as c0 then c1: on v1 two
    /// absorbs per element, on v2 one Keccak over the whole vector.
    pub fn absorb_fp2_vec(&mut self, values: &[Fp2]) {
        #[cfg(feature = "v2")]
        {
            let mut data = Vec::with_capacity(16 * values.len());
            for v in values {
                data.extend_from_slice(&v.c0.value().to_le_bytes());
                data.extend_from_slice(&v.c1.value().to_le_bytes());
            }
            self.mix(0x02, &data);
        }
        #[cfg(not(feature = "v2"))]
        for v in values {
            self.absorb_fp(v.c0);
            self.absorb_fp(v.c1);
        }
    }

    /// Absorb the query shape's id under its own tag, before the query grind
    /// (docs/16, docs/17 step 13), so one grind counts for one shape only.
    pub fn absorb_shape(&mut self, shape: u8) {
        self.mix(0x0A, &[shape]);
    }

    /// An exact stream of `n` base-field values under `tag` (docs/15): squeeze
    /// `state = keccak256(tag || state)`, read the four little-endian lanes
    /// in order, accept a lane below p and skip one at or above it, squeeze
    /// again when the lanes run out. Lanes left at the end are dropped.
    pub fn stream_fp(&mut self, tag: u8, n: usize) -> Vec<Fp> {
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            self.mix(tag, &[]);
            for v in accepted_lanes(&self.state) {
                if out.len() == n {
                    break;
                }
                out.push(v);
            }
        }
        out
    }

    /// An exact stream of `n` extension values under `tag`, each c0 then c1
    /// as consecutive accepted lanes.
    pub fn stream_fp2(&mut self, tag: u8, n: usize) -> Vec<Fp2> {
        let lanes = self.stream_fp(tag, 2 * n);
        (0..n)
            .map(|i| Fp2::new(lanes[2 * i], lanes[2 * i + 1]))
            .collect()
    }

    fn squeeze_u64(&mut self, tag: u8) -> u64 {
        self.mix(tag, &[]);
        let s = &self.state;
        u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
    }

    /// Draw a base-field challenge. Retained for query index derivation; fold and
    /// DEEP challenges use `challenge_fp2` for soundness (see below).
    pub fn challenge_fp(&mut self) -> Fp {
        #[cfg(feature = "v2")]
        {
            self.stream_fp(0x03, 1)[0]
        }
        #[cfg(not(feature = "v2"))]
        {
            Fp::from_u64(self.squeeze_u64(0x03))
        }
    }

    /// Draw a query index in `[0, bound)`. `bound` is a power of two in FRI, so
    /// masking is unbiased.
    pub fn challenge_index(&mut self, bound: usize) -> usize {
        (self.squeeze_u64(0x04) as usize) & (bound - 1)
    }

    /// Draw a challenge from the degree-2 extension `Fp2`. Fold and DEEP challenges
    /// are drawn here, not from the base field: the low-degree test's soundness
    /// error is `degree / |challenge field|`, so the base field caps it near
    /// `2^-64`, while `Fp2` (~`2^128`) reaches `2^-128`. The bound is proved in
    /// `Nonos.Stark.Soundness.the_soundness_error_is_below_the_degree`.
    pub fn challenge_fp2(&mut self) -> Fp2 {
        // v2: one exact stream under 0x06, c0 then c1 (docs/17); 0x07 unused.
        #[cfg(feature = "v2")]
        {
            self.stream_fp2(0x06, 1)[0]
        }
        #[cfg(not(feature = "v2"))]
        {
            let c0 = Fp::from_u64(self.squeeze_u64(0x06));
            let c1 = Fp::from_u64(self.squeeze_u64(0x07));
            Fp2::new(c0, c1)
        }
    }

    /// One extension challenge and its powers, alpha^0 through alpha^(n-1).
    /// The batched polynomial is nonzero of degree below `n` in alpha, so a
    /// random alpha misses its roots except with probability under `n` over
    /// `|Fp2|`, and the chain reads one draw where it read `n`.
    pub fn challenge_powers(&mut self, n: usize) -> Vec<Fp2> {
        let alpha = self.challenge_fp2();
        let mut v = Vec::with_capacity(n);
        let mut p = Fp2::ONE;
        for _ in 0..n {
            v.push(p);
            p = p * alpha;
        }
        v
    }

    /// Draw the seed another transcript starts from, so everything absorbed
    /// here is behind every challenge drawn there. A STARK hands this to FRI
    /// after its last draw: FRI's positions, drawn after FRI's nonce, then
    /// depend on the whole proof and are the positions the consistency check
    /// uses too. The receiver absorbs it as a digest, its first 24 bytes.
    pub fn challenge_seed(&mut self) -> [u8; 32] {
        self.mix(0x08, &[]);
        self.state
    }

    /// The grinding word for a nonce against the current state, not folded in until
    /// the winning nonce is committed. Keccak256 keeps the search a random oracle.
    /// It is `keccak256(0x05 || state || nonce le64)`'s first eight bytes read
    /// little endian, computed in lanes by `pow_lane` with no allocation.
    fn pow_word(&self, nonce: u64) -> u64 {
        pow_lane(&pow_template(0x05, &self.state), nonce)
    }

    /// The sponge state, for a known-answer vector a port checks itself
    /// against step by step. Nothing in the protocol reads it.
    pub fn state(&self) -> [u8; 32] {
        self.state
    }

    /// Prover-side grinding: search for a nonce whose grinding word has at least
    /// `bits` leading zero bits, then bind it into the transcript. This adds `bits`
    /// of proof-of-work to the query soundness, raising the cost of resampling
    /// challenges to forge a proof.
    pub fn grind(&mut self, bits: u32) -> u64 {
        let nonce = self.grind_search(bits);
        self.mix(0x05, &nonce.to_le_bytes());
        nonce
    }

    /// The proof-of-work search. Serially it is the smallest nonce meeting the
    /// work; over `bits` in the 30s that is billions of hashes on one core, the
    /// dominant cost of a deployment emit. The parallel form searches the nonce
    /// space in blocks across every core and returns the first (lowest) hit in
    /// each block, so it finds the identical smallest nonce as the serial search:
    /// bit-exact, spread across cores.
    #[cfg(not(feature = "parallel"))]
    fn grind_search(&self, bits: u32) -> u64 {
        let t = pow_template(0x05, &self.state);
        let mut nonce = 0u64;
        while pow_lane(&t, nonce).leading_zeros() < bits {
            nonce = nonce.wrapping_add(1);
        }
        nonce
    }

    #[cfg(feature = "parallel")]
    fn grind_search(&self, bits: u32) -> u64 {
        use rayon::prelude::*;
        /*
         * The block is the overshoot: the smallest winning nonce is only known
         * once its whole block is searched. At 2^26 a 25-bit search, whose
         * mean is half a block, did about twice its work, and a split grind
         * does eight of them. 2^20 bounds the waste at a million hashes a
         * search and is still tens of milliseconds of work per block per core.
         */
        const BLOCK: u64 = 1 << 20;
        let t = pow_template(0x05, &self.state);
        /*
         * On an arm64 core with the SHA3 instructions, nonces go two to a
         * permutation. Pairs are searched in order and the lower of a winning
         * pair is taken first, so the nonce found is the same smallest nonce.
         */
        #[cfg(target_arch = "aarch64")]
        if crate::hash::keccak_arm::sha3_available() {
            let mut base = 0u64;
            loop {
                let hit = (base / 2..(base + BLOCK) / 2)
                    .into_par_iter()
                    .find_first(|&k| {
                        let (a, b) = crate::hash::keccak_arm::pow_lanes2(&t, 2 * k, 2 * k + 1);
                        a.leading_zeros() >= bits || b.leading_zeros() >= bits
                    });
                if let Some(k) = hit {
                    let (a, _) = crate::hash::keccak_arm::pow_lanes2(&t, 2 * k, 2 * k + 1);
                    return if a.leading_zeros() >= bits {
                        2 * k
                    } else {
                        2 * k + 1
                    };
                }
                base += BLOCK;
            }
        }
        let mut base = 0u64;
        loop {
            let hit = (base..base + BLOCK)
                .into_par_iter()
                .find_first(|&n| pow_lane(&t, n).leading_zeros() >= bits);
            if let Some(n) = hit {
                return n;
            }
            base += BLOCK;
        }
    }

    /// Verifier-side grinding check: accept only if the nonce meets the `bits`
    /// proof-of-work, and on success bind it in exactly as the prover did so both
    /// draw the same subsequent challenges.
    pub fn verify_pow(&mut self, nonce: u64, bits: u32) -> bool {
        if self.pow_word(nonce).leading_zeros() < bits {
            return false;
        }
        self.mix(0x05, &nonce.to_le_bytes());
        true
    }
}

/// The lanes of a squeezed state a stream accepts (docs/15): the four
/// little-endian u64 lanes in order, each kept only when below p.
fn accepted_lanes(s: &[u8; 32]) -> Vec<Fp> {
    (0..4)
        .map(|lane| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&s[8 * lane..8 * lane + 8]);
            u64::from_le_bytes(b)
        })
        .filter(|&w| w < super::field::P)
        .map(Fp::from_u64)
        .collect()
}

/// Every transcript operation, in order, for a known-answer vector: a port
/// replays the same sequence and compares its state after each step. Only
/// with the `kat` feature, which no production build enables.
#[cfg(feature = "kat")]
pub mod kat {
    extern crate std;
    use alloc::vec::Vec;

    /// The tag recorded for `Transcript::new`: its data is the label, its
    /// state `keccak256(label)`.
    pub const NEW: u8 = 0x00;

    pub struct Event {
        /// 0x00 new, 0x01 digest, 0x02 field element, 0x03 base challenge,
        /// 0x04 query index, 0x05 grind nonce, 0x06 and 0x07 the halves of an
        /// extension challenge, 0x08 a seed for the next transcript.
        pub tag: u8,
        pub data: Vec<u8>,
        pub state: [u8; 32],
    }

    static LOG: std::sync::Mutex<Vec<Event>> = std::sync::Mutex::new(Vec::new());

    pub(super) fn record(tag: u8, data: &[u8], state: &[u8; 32]) {
        if let Ok(mut l) = LOG.lock() {
            l.push(Event {
                tag,
                data: data.to_vec(),
                state: *state,
            });
        }
    }

    /// Everything recorded so far, clearing the log.
    pub fn take() -> Vec<Event> {
        LOG.lock()
            .map(|mut l| core::mem::take(&mut *l))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A split grind is a chain: each nonce was found against the state with
    /// the one before it absorbed, so the same nonces in another order, or
    /// each checked against the one starting state, do not verify. A split
    /// whose searches could run side by side against one state would cost a
    /// forger one search's latency, not eight.
    #[test]
    fn a_split_grind_verifies_only_in_its_chain() {
        let bits = 10;
        let start = Transcript::new(b"split-grind");
        let mut prover = start.clone();
        let nonces: Vec<u64> = (0..8).map(|_| prover.grind(bits)).collect();

        let mut in_order = start.clone();
        assert!(
            nonces.iter().all(|&n| in_order.verify_pow(n, bits)),
            "the chain itself did not verify"
        );
        assert_eq!(
            in_order.state(),
            prover.state(),
            "the verifier ended somewhere else"
        );

        let mut reversed = start.clone();
        assert!(
            !nonces.iter().rev().all(|&n| reversed.verify_pow(n, bits)),
            "the chain verified out of order"
        );
        let unchained = nonces[1..]
            .iter()
            .all(|&n| start.clone().verify_pow(n, bits));
        assert!(
            !unchained,
            "later nonces verified against the starting state, unchained"
        );
    }

    /// A lane at or above p is skipped, not reduced: the stream takes the
    /// next lane, so every accepted value is uniform over the field.
    #[test]
    fn a_lane_at_or_above_p_is_skipped() {
        let p = super::super::field::P;
        let mut s = [0u8; 32];
        s[0..8].copy_from_slice(&p.to_le_bytes());
        s[8..16].copy_from_slice(&5u64.to_le_bytes());
        s[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
        s[24..32].copy_from_slice(&(p - 1).to_le_bytes());
        let got: Vec<u64> = accepted_lanes(&s).iter().map(|v| v.value()).collect();
        assert_eq!(got, [5, p - 1]);
    }

    /// On v2 an extension challenge is c0 then c1 from one 0x06 stream, and
    /// the lanes left over are dropped.
    #[cfg(feature = "v2")]
    #[test]
    fn an_extension_challenge_is_one_stream() {
        let mut t = Transcript::new(b"stream");
        let start = t.state();
        let c = t.challenge_fp2();
        let mut buf = alloc::vec![0x06u8];
        buf.extend_from_slice(&start);
        let first = keccak256(&buf);
        let lanes = accepted_lanes(&first);
        assert!(lanes.len() >= 2);
        assert_eq!((c.c0, c.c1), (lanes[0], lanes[1]));
        assert_eq!(t.state(), first, "one squeeze for two accepted lanes");
    }

    fn at(hex: &str) -> Transcript {
        let mut state = [0u8; 32];
        for (i, b) in state.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap_or(0);
        }
        Transcript { state }
    }

    /// The copy-constraint pair a two round proof draws after its region root,
    /// from a fixed state, on both paths. The on-chain verifier replays the same
    /// squeezes, so these are the known answers it is held to bit for bit.
    #[cfg(not(feature = "v2"))]
    #[test]
    fn the_copy_constraint_draws_match_the_chains() {
        let head = "038ce53ed5cfbb7bfae60af73ecd860637b608a8f6584c933cde31245df8104b";
        let mut t = at(head);
        let (b, g) = (t.challenge_fp2(), t.challenge_fp2());
        assert_eq!(
            [b.c0.value(), b.c1.value(), g.c0.value(), g.c1.value()],
            [
                114805819104899864,
                5745975392514496616,
                1664699787387098790,
                2840843379280941553
            ],
            "the Fp2 pair is not the chain's"
        );
        let mut t = at(head);
        let (b, g) = (t.challenge_fp(), t.challenge_fp());
        assert_eq!(
            [b.value(), g.value()],
            [15479558990150199839, 7722897680548534241],
            "the Fp pair is not the chain's"
        );
    }
}
