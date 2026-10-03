// NONOS Operating System (AGPL-3.0-or-later)

//! The sponge against published digests, and the grind lane against the sponge.

use super::*;
use alloc::vec::Vec;

fn hash(chunks: &[&[u8]]) -> [u8; 32] {
    let mut k = Keccak::new(512, 32, 0x01);
    for c in chunks {
        k.update(c);
    }
    k.finalize32()
}

/*
 * The sponge must not care how the input was handed to it.
 *
 * This is the property the type quietly did not need while `update` kept
 * every byte and permuted at the end, and it is the property that lets it
 * absorb as it goes. Sizes are chosen around the rate, 136 bytes here, so
 * the cases cover a partial block, an exact block, a block and a byte, and
 * a stream of single bytes, which is how a wide leaf actually feeds it.
 */
#[test]
fn a_chunked_update_hashes_the_same_as_one() {
    for len in [0usize, 1, 7, 135, 136, 137, 271, 272, 273, 1000, 21_192] {
        let data: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
        let whole = hash(&[&data]);
        let ones: Vec<&[u8]> = data.chunks(1).collect();
        let eights: Vec<&[u8]> = data.chunks(8).collect();
        let awkward: Vec<&[u8]> = data.chunks(137).collect();
        assert_eq!(whole, hash(&ones), "one byte at a time moved at {len}");
        assert_eq!(whole, hash(&eights), "eight at a time moved at {len}");
        assert_eq!(whole, hash(&awkward), "137 at a time moved at {len}");
    }
}

/// The lane form of the grinding hash is the sponge's, for every byte of
/// the state and every byte of the nonce, including the nonce byte that
/// crosses into lane 5 and the tag.
#[test]
fn pow_matches_the_sponge() {
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for tag in [0x05u8, 0x06, 0xff] {
        for _ in 0..64 {
            let mut state = [0u8; 32];
            for b in state.iter_mut() {
                *b = next() as u8;
            }
            let t = pow_template(tag, &state);
            for nonce in [0u64, 1, 0xff, 0x0100, u64::MAX, 1 << 56, next(), next()] {
                let mut msg = Vec::with_capacity(41);
                msg.push(tag);
                msg.extend_from_slice(&state);
                msg.extend_from_slice(&nonce.to_le_bytes());
                let h = hash(&[&msg]);
                let want = u64::from_le_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]]);
                assert_eq!(pow_lane(&t, nonce), want, "tag {tag:#x} nonce {nonce:#x}");
            }
        }
    }
}

/// A pinned digest, so a future change to the sponge fails here rather than
/// silently moving every commitment in the system.
#[test]
fn the_empty_and_abc_digests_are_pinned() {
    let empty = hash(&[&[]]);
    let abc = hash(&[b"abc"]);
    let hex = |v: &[u8]| {
        v.iter()
            .map(|b| alloc::format!("{b:02x}"))
            .collect::<alloc::string::String>()
    };
    /*
     * The published Keccak-256 vectors, which is the hash Ethereum uses
     * and therefore the one an on-chain verifier recomputes. These are not
     * the SHA3-256 values; the suffix here is 0x01, the legacy padding.
     * Pinned so a change to the sponge fails here instead of silently
     * moving every commitment in the system.
     */
    assert_eq!(
        hex(&empty),
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    );
    assert_eq!(
        hex(&abc),
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    );
}

/// How fast the sponge is, in the two shapes the prover feeds it: one
/// long buffer per leaf, and one eight byte value at a time per periodic
/// column. Not a correctness test; run with `--ignored --nocapture` and
/// read the two lines. A settlement proof hashes about a terabyte
/// through here, so a factor here is an hour on a large server.
#[test]
#[ignore]
#[cfg(feature = "parallel")]
fn throughput() {
    let data: Vec<u8> = (0..(32usize << 20)).map(|i| (i * 31 + 7) as u8).collect();
    let t = std::time::Instant::now();
    let mut k = Keccak::new(512, 32, 0x01);
    k.update(&data);
    let d = k.finalize32();
    let s = t.elapsed().as_secs_f64();
    std::println!(
        "KECCAK bulk {:.0} MB/s (digest byte {})",
        data.len() as f64 / 1e6 / s,
        d[0]
    );

    let cols = 2649usize;
    let leaves = 4096usize;
    let t = std::time::Instant::now();
    let mut acc = 0u64;
    for leaf in 0..leaves {
        let mut k = Keccak::new(512, 32, 0x01);
        for c in 0..cols {
            k.update(&((leaf * cols + c) as u64).to_le_bytes());
        }
        acc ^= k.finalize32()[0] as u64;
    }
    let s = t.elapsed().as_secs_f64();
    std::println!(
        "KECCAK streamed {:.0} leaves/s, {:.0} MB/s (acc {acc})",
        leaves as f64 / s,
        (leaves * cols * 8) as f64 / 1e6 / s
    );
}
