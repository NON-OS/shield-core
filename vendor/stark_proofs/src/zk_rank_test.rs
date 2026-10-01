// NONOS Operating System (AGPL-3.0-or-later)
//! The rank condition at chosen positions, on a pinned launch proof.
//!
//! docs/12-zero-knowledge.md, Section 4.4, and `Shield.Launch`: (R) holds for
//! positions in general position, and fails for every challenge when a
//! successor row's coset lands inside another query's layer-one leaf. These
//! place the queries on purpose and ask the wallet's own certificate.
#![cfg_attr(not(feature = "launch_v1"), allow(dead_code, unused_imports))]

use super::check_at;

const PROOF: &[u8] = include_bytes!("../../spec/wallet-vectors/transfer-eth/proof.bin");
const PUBLICS: &str = include_str!("../../spec/wallet-vectors/transfer-eth/publics.json");

/// The evaluation domain and the step to a row's successor: the trace
/// generator is omega^(N / 2^13) on a domain of 2^23.
const N: usize = 1 << 23;
const SUCC: usize = N >> 13;
const QUERIES: usize = 19;

fn publics() -> Vec<u64> {
    let open = PUBLICS.find('[').unwrap_or(0) + 1;
    let close = PUBLICS[open..].find(']').map(|i| open + i).unwrap_or(open);
    PUBLICS[open..close]
        .split(',')
        .filter_map(|w| w.trim().parse().ok())
        .collect()
}

/// Positions with distinct leaves at every layer, from a fixed seed.
fn spread(seed: u64) -> Vec<usize> {
    let mut x = seed ^ 0x9E37_79B9_7F4A_7C15;
    let mut out: Vec<usize> = Vec::with_capacity(QUERIES);
    while out.len() < QUERIES {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let p = (x as usize) % N;
        if out.iter().all(|&q| q % (N >> 10) != p % (N >> 10)) {
            out.push(p);
        }
    }
    out
}

fn holds(positions: Vec<usize>) -> bool {
    match check_at(PROOF, &publics(), 3, Some(positions)) {
        Ok(r) => r.holds,
        Err(why) => panic!("the pinned proof did not replay: {why}"),
    }
}

/// The proof's own positions, as the wallet checks it before sending.
#[test]
#[cfg(feature = "launch_v1")]
fn the_pinned_proof_passes_its_own_check() {
    let r = check_at(PROOF, &publics(), 3, None).unwrap_or_else(|why| panic!("{why}"));
    assert!(r.holds, "the pinned proof failed its own rank check: {r:?}");
}

#[test]
#[cfg(feature = "launch_v1")]
fn the_rank_holds_at_positions_in_general_position() {
    for seed in 1..=3 {
        assert!(
            holds(spread(seed)),
            "(R) failed at spread positions, seed {seed}"
        );
    }
}

/// Query 1's leaf at layer one contains the fourth power of query 0's
/// successor row, at another of its four points. The masks vanish on that
/// whole successor coset and cannot move the value there; the simulator can.
#[test]
#[cfg(feature = "launch_v1")]
fn a_successor_coset_inside_another_leaf_breaks_the_rank() {
    let mut p = spread(1);
    p[1] = (p[0] + SUCC + N / 16) % N;
    assert!(
        !holds(p),
        "(R) held although a successor coset lies inside another query's leaf"
    );
}

/// The fourth landing is harmless: when the successor coset is the other
/// query's own layer-zero coset, both sides already vanish there.
#[test]
#[cfg(feature = "launch_v1")]
fn a_successor_coset_on_another_querys_own_point_keeps_the_rank() {
    let mut p = spread(1);
    p[1] = (p[0] + SUCC) % N;
    assert!(
        holds(p),
        "(R) failed where the successor coset is another query's own leaf"
    );
}

/// The batched echelon reaches the rank the one-row-at-a-time echelon does at
/// every stopping point, on matrices built to be rank deficient, with repeated
/// rows and targets reached early and never.
#[test]
fn the_batched_echelon_matches_the_reference() {
    use super::{Batched, Echelon};
    use crate::crypto::stark::field::Fp;
    let mut x = 0x2545_F491_4F6C_DD1Du64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for trial in 0..60 {
        let width = 8 + (next() % 40) as usize;
        let n = 1 + (next() % 70) as usize;
        let rank_cap = 1 + (next() % width as u64) as usize;
        // Rows from a random basis of rank_cap vectors, so the rank is capped.
        let basis: Vec<Vec<Fp>> = (0..rank_cap)
            .map(|_| (0..width).map(|_| Fp::from_u64(next() % 7)).collect())
            .collect();
        let rows: Vec<Vec<Fp>> = (0..n)
            .map(|_| {
                let mut v = vec![Fp::ZERO; width];
                for b in &basis {
                    let c = Fp::from_u64(next() % 5);
                    for (a, y) in v.iter_mut().zip(b) {
                        *a = *a + c * *y;
                    }
                }
                v
            })
            .collect();
        let target = 1 + (next() % (width as u64 + 4)) as usize;

        let mut reference = Echelon { rows: Vec::new() };
        for r in &rows {
            if reference.rows.len() >= target {
                break;
            }
            reference.add(r.clone());
        }
        let mut batched = Batched { rows: Vec::new() };
        let mut from = 0usize;
        while batched.rows.len() < target && from < rows.len() {
            let take = (1 + (next() % 9) as usize).min(rows.len() - from);
            batched.extend(rows[from..from + take].to_vec(), target);
            from += take;
        }
        assert_eq!(
            batched.rows.len(),
            reference.rows.len(),
            "trial {trial}: width {width}, rows {n}, cap {rank_cap}, target {target}"
        );
    }
}
