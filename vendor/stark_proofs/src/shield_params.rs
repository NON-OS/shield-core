// NONOS Operating System (AGPL-3.0-or-later)
//! The soundness points, each stated once. Every prove and verify reads one of
//! these, so no file restates the numbers.
//!
//! `inner` is the join-split a sender proves, verified inside the settlement
//! outer. `settlement` is the outer the chain verifies, at format 5. Rate and
//! bits: docs/12-soundness.md.

/// The inner join-split: 32 queries at rate 1/16 with a 16-bit grind, 144
/// conjectured and 80 provable bits.
pub mod inner {
    /// FRI queries drawn.
    pub const N_QUERIES: usize = 32;
    /// Proof-of-work bits on the FRI transcript.
    pub const GRIND_BITS: u32 = 16;
    /// Extra blowup over the minimal rate-one-half domain: rate 1/16.
    pub const EXTRA_BLOWUP_BITS: u32 = 3;
}

/// The settlement outer, point B: 14 queries at rate 1/128 with a 32-bit grind,
/// 130 conjectured and 81 provable bits, over a 2^28 domain.
pub mod settlement {
    /// FRI queries drawn.
    pub const N_QUERIES: usize = 14;
    /// Proof-of-work bits on the FRI transcript.
    pub const GRIND_BITS: u32 = 32;
    /// Extra blowup over the minimal rate-one-half domain: rate 1/128.
    pub const EXTRA_BLOWUP_BITS: u32 = 6;
}

/// Point A: a spend proved directly for the chain. 19 queries at rate 1/64
/// with a 28-bit grind before the query draw; on the deployed transcript a
/// 19-bit grind before the DEEP draw and 21 bits before each folding challenge
/// (`fri_ext`). Round by round that is 80.8 bits for the query draw and 80.1
/// provable, docs/12-soundness.md Section 2.
pub mod direct {
    /// FRI queries drawn.
    pub const N_QUERIES: usize = 19;
    /// Proof-of-work bits before the query draw.
    pub const GRIND_BITS: u32 = 28;
    /// Extra blowup over the minimal rate-one-half domain: rate 1/64.
    pub const EXTRA_BLOWUP_BITS: u32 = 5;
}

/// Points no settlement uses: the fast point tests run at, the transfer inner
/// the `Transfer` recursion proves over, and the outer under the wrap.
pub mod rehearsal {
    /// Rate one half, grind 8: tests, gates and local emits.
    pub mod dev {
        pub const N_QUERIES: usize = 32;
        pub const GRIND_BITS: u32 = 8;
        pub const EXTRA_BLOWUP_BITS: u32 = 0;
    }

    /// 64 queries at rate 1/4, grind 16: 144 conjectured and 80 provable bits
    /// over a quarter of the inner domain.
    pub mod transfer {
        pub const N_QUERIES: usize = 64;
        pub const GRIND_BITS: u32 = 16;
        pub const EXTRA_BLOWUP_BITS: u32 = 1;
    }

    /// 16 queries at rate 1/64, grind 32: 128 conjectured and 80 provable bits.
    pub mod under_wrap {
        pub const N_QUERIES: usize = 16;
        pub const GRIND_BITS: u32 = 32;
        pub const EXTRA_BLOWUP_BITS: u32 = 5;
    }
}

/// Conjectured FRI security in bits: `q (1 + extra) + grind`. The rate is
/// `2^-(1 + extra)`, so each query yields `1 + extra` bits under the FRI
/// conjecture. Quote it only beside [`provable_bits`].
pub const fn security_bits(n_queries: usize, grind_bits: u32, extra_blowup_bits: u32) -> u32 {
    n_queries as u32 * (1 + extra_blowup_bits) + grind_bits
}

/// The query phase's provable bits by the halved count: `q (1 + extra) / 2 +
/// grind`. Inside the proven list-decoding radius a query yields about half
/// the conjectured bits, and the grind counts because every query is drawn
/// after it. This is one term of the bound, not the bound: FRI's commit phase
/// is the other, and at these domains it is smaller unless the commit rounds
/// are ground. docs/12-soundness.md, Section 2.1, has both.
pub const fn provable_bits(n_queries: usize, grind_bits: u32, extra_blowup_bits: u32) -> u32 {
    (n_queries as u32 * (1 + extra_blowup_bits)) / 2 + grind_bits
}

#[cfg(test)]
mod tests {
    use super::rehearsal::{dev, transfer, under_wrap};
    use super::*;

    /// The settlement point is point B, and its bits are the published ones.
    #[test]
    fn the_settlement_point_is_point_b() {
        let (q, g, b) = (settlement::N_QUERIES, settlement::GRIND_BITS, settlement::EXTRA_BLOWUP_BITS);
        assert_eq!((q, g, b), (14, 32, 6), "the settlement point moved");
        assert_eq!(security_bits(q, g, b), 130);
        assert_eq!(provable_bits(q, g, b), 81);
    }

    /// Point A is 19 / 28 / 5. Its query phase alone is 85 by the halved
    /// count; round by round it is 80.1, docs/12-soundness.md Section 2.
    #[test]
    fn the_direct_point_is_the_launch_point() {
        let (q, g, b) = (direct::N_QUERIES, direct::GRIND_BITS, direct::EXTRA_BLOWUP_BITS);
        assert_eq!((q, g, b), (19, 28, 5), "the launch point moved");
        assert_eq!(security_bits(q, g, b), 142);
        assert_eq!(provable_bits(q, g, b), 85);
    }

    /// The inner point clears 128 conjectured and 80 provable bits.
    #[test]
    fn the_inner_point_is_at_least_128_bit() {
        let (q, g, b) = (inner::N_QUERIES, inner::GRIND_BITS, inner::EXTRA_BLOWUP_BITS);
        assert_eq!(security_bits(q, g, b), 144);
        assert_eq!(provable_bits(q, g, b), 80);
    }

    /// Every point but the development one clears 80 bits without the conjecture.
    #[test]
    fn every_point_clears_80_bits_without_the_conjecture() {
        for (name, q, g, b) in [
            ("inner", inner::N_QUERIES, inner::GRIND_BITS, inner::EXTRA_BLOWUP_BITS),
            ("settlement", settlement::N_QUERIES, settlement::GRIND_BITS, settlement::EXTRA_BLOWUP_BITS),
            ("transfer", transfer::N_QUERIES, transfer::GRIND_BITS, transfer::EXTRA_BLOWUP_BITS),
            ("under_wrap", under_wrap::N_QUERIES, under_wrap::GRIND_BITS, under_wrap::EXTRA_BLOWUP_BITS),
        ] {
            let bits = provable_bits(q, g, b);
            assert!(bits >= 80, "{name} is {bits} provable bits, below the 80-bit floor");
        }
    }

    /// The development point is weaker than the inner point, so no test runs at
    /// production cost by accident.
    #[test]
    fn the_development_point_is_below_the_inner_point() {
        let dev_bits = security_bits(dev::N_QUERIES, dev::GRIND_BITS, dev::EXTRA_BLOWUP_BITS);
        let inner_bits = security_bits(inner::N_QUERIES, inner::GRIND_BITS, inner::EXTRA_BLOWUP_BITS);
        assert!(dev_bits < inner_bits, "the development point is not weaker than the inner point");
    }

    /// The transfer inner is never weaker than the inner join-split.
    #[test]
    fn the_transfer_point_is_not_weaker_than_the_inner_point() {
        let t = security_bits(transfer::N_QUERIES, transfer::GRIND_BITS, transfer::EXTRA_BLOWUP_BITS);
        let i = security_bits(inner::N_QUERIES, inner::GRIND_BITS, inner::EXTRA_BLOWUP_BITS);
        assert!(t >= i, "transfer soundness is {t} bits, below the inner's {i}");
    }

    /// The transfer domain is smaller than the inner domain, or it has no reason to exist.
    const _: () = assert!(
        transfer::EXTRA_BLOWUP_BITS < inner::EXTRA_BLOWUP_BITS,
        "the transfer domain is not smaller than the inner domain"
    );
}
