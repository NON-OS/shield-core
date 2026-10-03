// NONOS Operating System (AGPL-3.0-or-later)

//! Domain-separated leaf and node hashing for the Merkle commitment. Keccak256 is
//! the hash, already the EVM-native hash, so the on-chain verifier recomputes leaves and nodes with a
//! single native opcode instead of a costly in-Solidity hash.

use super::super::field::{Fp, Fp2};
use crate::hash::Keccak;

const DOM_LEAF: &[u8] = b"NONOS-STARK-MERKLE-LEAF";
const DOM_LEAF_EXT: &[u8] = b"NONOS-STARK-MERKLE-LEAF-EXT";
const DOM_LEAF_PAIR: &[u8] = b"NONOS-STARK-MERKLE-LEAF-PAIR";
const DOM_LEAF_QUAD: &[u8] = b"NONOS-STARK-MERKLE-LEAF-QUAD";
const DOM_LEAF_OCT: &[u8] = b"NONOS-STARK-MERKLE-LEAF-OCT";
const DOM_LEAF_GROUP: &[u8] = b"NONOS-STARK-MERKLE-LEAF-GROUP";
const DOM_LEAF_WIDE: &[u8] = b"NONOS-STARK-MERKLE-LEAF-WIDE";
const DOM_LEAF_PERIODIC: &[u8] = b"NONOS-STARK-PERIODIC-WIDE";
const DOM_NODE: &[u8] = b"NONOS-STARK-MERKLE-NODE";

/// The bytes of a digest that are the digest. Keccak squeezes 32 and the
/// first `DIGEST_BYTES` are kept, the rest of the array zero: a node hashes
/// its children's kept bytes, the wire carries the kept bytes, the transcript
/// absorbs the kept bytes. Path nodes are most of a proof, so this is the
/// largest single lever on its size; 24 buys 96 bit collision resistance
/// over a provable floor of 80, where 32 bought 128 the proof could not use.
///
/// `digest32` keeps all 32, for the `fri8` build: shared paths (format 6) pay for the
/// wider digest. It is a build, not a setting, because the width moves every
/// root, the periodic one included, and the parameter identity hashes it, so
/// a proof at one width is refused by a verifier built for the other.
#[cfg(not(feature = "digest32"))]
pub const DIGEST_BYTES: usize = 24;
#[cfg(feature = "digest32")]
pub const DIGEST_BYTES: usize = 32;

/// A sponge's output as a digest: the kept bytes, the tail zero.
fn digest(k: Keccak) -> [u8; 32] {
    let mut d = k.finalize32();
    d[DIGEST_BYTES..].fill(0);
    d
}

/// Hash a field element into a leaf digest, domain-separated from node hashing
/// so a leaf can never be reinterpreted as an internal node.
pub(super) fn hash_leaf(leaf: Fp) -> [u8; 32] {
    let mut k = Keccak::new(512, 32, 0x01);
    k.update(DOM_LEAF);
    k.update(&leaf.value().to_le_bytes());
    digest(k)
}

/// Hash an extension-field element into a leaf digest: both lanes under a distinct
/// domain, so a folded FRI layer commits like a base layer but can never be
/// confused with one, an internal node, or a differently-shaped leaf.
pub fn hash_leaf_ext(leaf: Fp2) -> [u8; 32] {
    let mut k = Keccak::new(512, 32, 0x01);
    k.update(DOM_LEAF_EXT);
    k.update(&leaf.c0.value().to_le_bytes());
    k.update(&leaf.c1.value().to_le_bytes());
    digest(k)
}

/// Hash a folding pair into one leaf: the value at a position and the value at
/// its negation, which a fold always reads together.
///
/// A query then pays one path per layer instead of one per opening. The saving
/// is the fold factor, so two at a radix two fold and rising with the radix.
/// Without it, raising the fold factor makes a proof larger rather than
/// smaller. Its own domain, so a pair leaf cannot be read as a single one.
pub(super) fn hash_leaf_pair(a: Fp2, b: Fp2) -> [u8; 32] {
    let mut k = Keccak::new(512, 32, 0x01);
    k.update(DOM_LEAF_PAIR);
    for v in [a.c0, a.c1, b.c0, b.c1] {
        k.update(&v.value().to_le_bytes());
    }
    digest(k)
}

/// Hash a fold quad into one leaf: the four values a radix-four fold reads
/// together, at stride a quarter of the layer.
///
/// A query pays one path per layer whatever the fold factor, so the factor
/// is only a lever once a leaf holds everything the fold consumes. At radix
/// two that was the pair; at four it is this. Its own domain, so a quad leaf
/// cannot be read as a pair leaf, which would let a prover present a layer
/// folded one way as a layer folded the other.
pub fn hash_leaf_quad(v: [Fp2; 4]) -> [u8; 32] {
    hash_leaf_group(&v)
}

/// A FRI leaf of any fold: the values a fold reads, under a domain of their
/// count. Four is the quad leaf byte for byte, so radix 4 is unchanged; eight
/// has its own tag, so a leaf of one fold cannot be read as a leaf of another.
pub fn hash_leaf_group(v: &[Fp2]) -> [u8; 32] {
    let mut k = Keccak::new(512, 32, 0x01);
    match v.len() {
        4 => k.update(DOM_LEAF_QUAD),
        8 => k.update(DOM_LEAF_OCT),
        n => {
            k.update(DOM_LEAF_GROUP);
            k.update(&(n as u32).to_le_bytes());
        }
    }
    for x in v {
        k.update(&x.c0.value().to_le_bytes());
        k.update(&x.c1.value().to_le_bytes());
    }
    digest(k)
}

/// Hash a whole trace row into one leaf: every column's canonical value as an
/// 8-byte little-endian integer, tightly packed in column order, under a domain
/// distinct from the single-value leaf so a wide leaf can never be confused with a
/// base leaf, an extension leaf, or an internal node. This is the commitment shape
/// the on-chain verifier recomputes once per query instead of one path per column.
pub fn hash_leaf_wide(row: &[Fp]) -> [u8; 32] {
    let mut k = Keccak::new(512, 32, 0x01);
    k.update(DOM_LEAF_WIDE);
    for v in row {
        k.update(&v.value().to_le_bytes());
    }
    digest(k)
}

/// Hash a row of preprocessed periodic-column values into one leaf: identical
/// packing to the wide trace leaf under its own domain, so the structural
/// periodic commitment a verifier bakes as a constant can never be read as a
/// trace leaf.
pub fn hash_leaf_wide_periodic(row: &[Fp]) -> [u8; 32] {
    let mut k = Keccak::new(512, 32, 0x01);
    k.update(DOM_LEAF_PERIODIC);
    for v in row {
        k.update(&v.value().to_le_bytes());
    }
    digest(k)
}

/// The wide periodic leaf hash absorbed one value at a time. `hash_leaf_wide_periodic`
/// hashes a row whole; this pushes the same bytes in the same order, the tag and then
/// each value's little endian encoding, through the same sponge, so a leaf built from
/// columns streamed past it in column order finalises to the identical digest. It is
/// what lets a committer hold one chunk of columns at a time instead of all of them.
pub struct PeriodicLeafHasher(Keccak);

impl PeriodicLeafHasher {
    pub fn new() -> PeriodicLeafHasher {
        let mut k = Keccak::new(512, 32, 0x01);
        k.update(DOM_LEAF_PERIODIC);
        PeriodicLeafHasher(k)
    }

    pub fn absorb(&mut self, v: Fp) {
        self.0.update(&v.value().to_le_bytes());
    }

    pub fn finalize(self) -> [u8; 32] {
        digest(self.0)
    }
}

impl Default for PeriodicLeafHasher {
    fn default() -> PeriodicLeafHasher {
        PeriodicLeafHasher::new()
    }
}

/// Hash two child digests into their parent, with a distinct domain tag:
/// the tag, then each child's kept bytes.
pub(super) fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut k = Keccak::new(512, 32, 0x01);
    k.update(DOM_NODE);
    k.update(&left[..DIGEST_BYTES]);
    k.update(&right[..DIGEST_BYTES]);
    digest(k)
}

#[cfg(test)]
mod kat_tests {
    use super::*;
    extern crate std;

    /// A known answer for the wide periodic leaf and a two leaf root, so a
    /// second implementation can be checked against a number rather than a
    /// description. The leaf is the domain tag followed by each value's
    /// canonical little endian 8 bytes, the first `DIGEST_BYTES` of keccak256
    /// over the whole buffer; the node is its own tag followed by the two
    /// child digests' kept bytes.
    #[test]
    fn the_periodic_leaf_kat() {
        let a = [
            Fp::from_u64(1),
            Fp::from_u64(2),
            Fp::from_u64(3),
            Fp::from_u64(4),
        ];
        let b = [
            Fp::from_u64(0xFFFF_FFFF_0000_0000),
            Fp::from_u64(7),
            Fp::from_u64(0),
            Fp::from_u64(0xFFFF_FFFF_0000_0000),
        ];
        let la = hash_leaf_wide_periodic(&a);
        let lb = hash_leaf_wide_periodic(&b);
        let root = hash_node(&la, &lb);
        let hex = |d: &[u8; 32]| {
            let mut s = std::string::String::new();
            for x in d[..DIGEST_BYTES].iter() {
                s.push_str(&std::format!("{x:02x}"));
            }
            s
        };
        std::println!("PERIODIC_LEAF  [1,2,3,4]                 = {}", hex(&la));
        std::println!("PERIODIC_LEAF  [p-1 as 2^64-2^32, 7,0,.] = {}", hex(&lb));
        std::println!("PERIODIC_ROOT2 node(la, lb)              = {}", hex(&root));
    }
}
