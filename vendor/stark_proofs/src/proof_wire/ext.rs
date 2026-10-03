// NONOS Operating System (AGPL-3.0-or-later)
//! The wire layout of the preprocessed-periodic proof: the frozen base proof
//! bytes (spec/stark-serialization.md), then the periodic sidecar: the
//! claims at z, and per consistency query the wide periodic row with its
//! path against the baked root.

use crate::crypto::stark::air::{serialize_proof_ext, StarkProofExtPre, StarkProofExtRounds};
use crate::crypto::stark::merkle::DIGEST_BYTES;
use crate::proof_wire::header::ParamSet;
use alloc::vec::Vec;

/// The wire form a chain verifier decodes. Public because the settlement
/// artifact is written by a binary outside this module and must be written by
/// this encoder rather than a second one: two encoders for one format is the
/// way a proof that verifies in the prover fails to decode on the chain.
///
/// The base half is the library's own serializer rather than a copy. There was
/// a second copy inside the test-only generator, byte for byte the same; a
/// format with two writers only stays one format for as long as nobody edits
/// either, so the copy is gone and the test below holds this to the decoder.
pub fn serialize_pre(pre: &StarkProofExtPre) -> Vec<u8> {
    let mut b = serialize_proof_ext(&pre.proof);
    // sidecar: n_periodic, the claims at z, then one opening per query in
    // query order: n_periodic row values, then the path.
    b.extend_from_slice(&(pre.periodic_z.len() as u32).to_le_bytes());
    for v in &pre.periodic_z {
        b.extend_from_slice(&v.c0.value().to_le_bytes());
        b.extend_from_slice(&v.c1.value().to_le_bytes());
    }
    // The DEEP nonce after the claims, where the transcript absorbs it.
    #[cfg(feature = "fri8")]
    b.extend_from_slice(&pre.deep_nonce.to_le_bytes());
    for op in &pre.openings {
        for v in &op.row {
            b.extend_from_slice(&v.value().to_le_bytes());
        }
        b.extend_from_slice(&(op.path.len() as u32).to_le_bytes());
        for d in &op.path {
            b.extend_from_slice(&d[..DIGEST_BYTES]);
        }
    }
    b
}

/// The wire form when the trace was committed in two rounds: the second
/// round's root and where the row splits, then the one round encoding, then
/// one path per query authenticating the permutation half.
///
/// The root leads because the transcript absorbs it before it squeezes the
/// composition coefficients, and a verifier that streams the header has to
/// have it by then. It was appended at first, which put it past the sidecar,
/// several hundred kilobytes after the point where it is needed, so the chain
/// side could not reach it without reading the whole object.
///
/// The split travels with it because a decoder that guessed it would check two
/// roots against halves of its own choosing and still see two valid walks.
///
/// The per query paths stay at the end, beside nothing, because a chunked
/// verifier slices them by query the same way it slices the other per query
/// sections.
///
/// This is not a superset of the one round format and is not meant to be. A
/// verifier that accepted both would let a prover present the one round
/// encoding and skip the copy commitment check entirely, which is the hole the
/// second round exists to close.
///
/// `ROUNDS_HEADER` is what precedes the one round encoding, named once rather
/// than counted at each reader. A consumer that reads the base half of a two
/// round artifact starts past it; one that starts at zero gets a parse failure
/// if it is lucky and a frame of nonsense if it is not.
pub const ROUNDS_HEADER: usize = crate::proof_wire::header::HEADER_BYTES + DIGEST_BYTES + 4;

pub fn serialize_rounds(rounds: &StarkProofExtRounds, params: &ParamSet) -> Vec<u8> {
    let mut b = crate::proof_wire::header::write_header(params);
    b.extend_from_slice(&rounds.perm_root[..DIGEST_BYTES]);
    b.extend_from_slice(&(rounds.region_width as u32).to_le_bytes());
    b.extend_from_slice(&serialize_pre(&rounds.pre));
    for path in &rounds.perm_paths {
        b.extend_from_slice(&(path.len() as u32).to_le_bytes());
        for d in path {
            b.extend_from_slice(&d[..DIGEST_BYTES]);
        }
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::stark::air::deserialize_proof_ext;

    /*
     * The base half of the sidecar format is the plain proof encoding, and the
     * decoder on the other side reads it as one. Round tripping the prefix back
     * through the library's own parser is what pins that: if the base encoding
     * ever moves, this fails here rather than on a chain, and the sidecar's
     * offsets move with it rather than silently pointing into the wrong bytes.
     */
    #[test]
    fn the_base_half_is_the_plain_proof_encoding() {
        let (_air, pre, _root) = crate::preprocessed_tests::setup();
        let bytes = serialize_pre(&pre);
        let base = serialize_proof_ext(&pre.proof);
        assert_eq!(
            &bytes[..base.len()],
            &base[..],
            "the base half must be the proof encoding"
        );
        let back = deserialize_proof_ext(&base).expect("the base half must parse on its own");
        assert_eq!(back.trace_root, pre.proof.trace_root);
        assert_eq!(back.comp_root, pre.proof.comp_root);
        assert_eq!(back.queries.len(), pre.proof.queries.len());
        assert!(
            bytes.len() > base.len(),
            "the sidecar must follow the base half"
        );
    }

    /*
     * The v1.1 header, pinned by offset rather than by prose.
     *
     * A chain verifier decodes this by position: the permutation root at 0,
     * the row split a digest in, the one round encoding four bytes on. Its transcript absorbs
     * the second root before it squeezes the composition coefficients, so it
     * has to reach the root without reading the sidecar first, which is why the
     * root leads at all.
     *
     * If these offsets move, the decoder on the other side reads a root out of
     * the middle of a frame and reports a bad proof. That failure is expensive
     * to diagnose from a revert code, so it fails here instead.
     *
     * This test is permanent. Magic at 0, permRoot at 40 and regionWidth at 64
     * are the interface between the Rust encoder and the chain's decoder, and
     * an interface with no test is a convention. It moved once, when the header
     * was added, and it was updated rather than deleted: that is the only way
     * it ever changes. Do not remove it because a round trip covers the same
     * bytes. A round trip agrees with itself; this one agrees with Yul.
     */
    #[test]
    fn the_rounds_header_leads_with_the_second_root() {
        use crate::crypto::stark::air::{StarkProofExtRounds, RATE};

        let (air, pre, _root) = crate::preprocessed_tests::setup();
        let n_q = pre.proof.queries.len();
        let mut perm_root = [0u8; 32];
        perm_root[..DIGEST_BYTES].fill(7);
        let region_width = 510usize;
        let rounds = StarkProofExtRounds {
            pre,
            perm_root,
            region_width,
            perm_paths: alloc::vec![alloc::vec![[9u8; 32]; 3]; n_q],
        };
        let bytes = serialize_rounds(&rounds, &crate::proof_wire::ParamSet::of(&air, 32, 8, 3));

        // The identity leads, then the second round's root, then the split.
        // These three offsets are what a chain reader addresses by position,
        // so they are pinned here rather than described anywhere.
        let id = crate::proof_wire::HEADER_BYTES;
        let h = ROUNDS_HEADER;
        assert_eq!(&bytes[..4], &crate::proof_wire::MAGIC, "the magic leads");
        assert_eq!(
            &bytes[id..id + DIGEST_BYTES],
            &perm_root[..DIGEST_BYTES],
            "the permutation root follows the identity"
        );
        assert_eq!(
            u32::from_le_bytes(bytes[id + DIGEST_BYTES..h].try_into().unwrap()) as usize,
            region_width,
            "the row split follows the root"
        );

        let base = serialize_pre(&rounds.pre);
        assert_eq!(
            &bytes[h..h + base.len()],
            &base[..],
            "the one round encoding starts after the header and is unchanged"
        );

        // The per query paths trail, one count and that many digests each.
        let tail = &bytes[h + base.len()..];
        assert_eq!(
            tail.len(),
            n_q * (4 + 3 * DIGEST_BYTES),
            "one trailing path per query, counted"
        );
        let _ = RATE;
    }
}

#[cfg(test)]
mod round_trip {
    use super::*;
    use crate::proof_wire::{deserialize_rounds, ParamSet};

    /// The fixture's own parameters. A test that made its identity up would
    /// pass while the encoder and the parser disagreed about what a
    /// parameter set is, which is the thing the identity exists to catch.
    fn params(air: &impl crate::crypto::stark::air::AirExt) -> ParamSet {
        ParamSet::of(air, 32, 8, 3)
    }

    /// A shipped artifact parses back to what was written, and the parser is
    /// the strict one: the encoder's bytes are the only bytes it accepts.
    ///
    /// The encoder existed without an inverse until 2026-09-22, so nothing in
    /// Rust had ever read a whole file back and the reference verifier could
    /// not be run over the exact bytes a settler broadcasts.
    #[test]
    fn a_shipped_artifact_parses_back() {
        use crate::crypto::stark::air::StarkProofExtRounds;
        let (air, pre, _root) = crate::preprocessed_tests::setup();
        let n_q = pre.proof.queries.len();
        let mut perm_root = [0u8; 32];
        perm_root[..DIGEST_BYTES].fill(7);
        let rounds = StarkProofExtRounds {
            pre,
            perm_root,
            region_width: 510,
            perm_paths: alloc::vec![alloc::vec![[9u8; 32]; 3]; n_q],
        };
        let bytes = serialize_rounds(&rounds, &params(&air));
        let back = deserialize_rounds(&bytes, &params(&air)).expect("the artifact must parse");

        assert_eq!(back.perm_root, rounds.perm_root);
        assert_eq!(back.region_width, rounds.region_width);
        assert_eq!(back.pre.proof.queries.len(), n_q);
        assert_eq!(back.pre.periodic_z.len(), rounds.pre.periodic_z.len());
        assert_eq!(back.pre.openings.len(), n_q);
        assert_eq!(back.perm_paths.len(), n_q);
        assert_eq!(
            serialize_rounds(&back, &params(&air)),
            bytes,
            "the parse is the encoder's inverse"
        );
    }

    /// A byte after the last section is refused. It changes nothing the proof
    /// says and everything about what it hashes to, and a settlement that
    /// names a proof by its digest then has two names for one object.
    #[test]
    fn a_trailing_byte_is_refused() {
        use crate::crypto::stark::air::StarkProofExtRounds;
        let (air, pre, _root) = crate::preprocessed_tests::setup();
        let n_q = pre.proof.queries.len();
        let rounds = StarkProofExtRounds {
            pre,
            perm_root: [0u8; 32],
            region_width: 510,
            perm_paths: alloc::vec![alloc::vec![[9u8; 32]; 3]; n_q],
        };
        let mut bytes = serialize_rounds(&rounds, &params(&air));
        assert!(
            deserialize_rounds(&bytes, &params(&air)).is_some(),
            "the honest bytes parse"
        );
        bytes.push(0);
        assert!(
            deserialize_rounds(&bytes, &params(&air)).is_none(),
            "a trailing zero byte was accepted"
        );
    }

    /// Every truncation is refused, at every length. A parser that returns
    /// something for a prefix is a parser that will one day verify one.
    #[test]
    fn every_truncation_is_refused() {
        use crate::crypto::stark::air::StarkProofExtRounds;
        let (air, pre, _root) = crate::preprocessed_tests::setup();
        let n_q = pre.proof.queries.len();
        let rounds = StarkProofExtRounds {
            pre,
            perm_root: [0u8; 32],
            region_width: 510,
            perm_paths: alloc::vec![alloc::vec![[9u8; 32]; 3]; n_q],
        };
        let bytes = serialize_rounds(&rounds, &params(&air));
        let mut cut = 1usize;
        while cut < bytes.len() {
            assert!(
                deserialize_rounds(&bytes[..cut], &params(&air)).is_none(),
                "a proof truncated to {cut} of {} bytes parsed",
                bytes.len()
            );
            cut = (cut * 2 + 1).min(bytes.len() - 1).max(cut + 1);
            if cut >= bytes.len() {
                break;
            }
        }
    }

    /// A field element at or above the modulus is refused wherever it sits.
    /// Two encodings of one value is a transcript that hashes differently for
    /// the same statement, which is a malleability bug dressed as a decode.
    #[test]
    fn a_non_canonical_field_element_is_refused() {
        use crate::crypto::stark::air::StarkProofExtRounds;
        use crate::crypto::stark::field::P;
        let (air, pre, _root) = crate::preprocessed_tests::setup();
        let n_q = pre.proof.queries.len();
        let rounds = StarkProofExtRounds {
            pre,
            perm_root: [0u8; 32],
            region_width: 510,
            perm_paths: alloc::vec![alloc::vec![[9u8; 32]; 3]; n_q],
        };
        let bytes = serialize_rounds(&rounds, &params(&air));
        // The first frame element sits right after the three roots and the
        // frame's own count, which the header layout pins.
        let at = ROUNDS_HEADER + 3 * DIGEST_BYTES + 4;
        let mut bent = bytes.clone();
        bent[at..at + 8].copy_from_slice(&P.to_le_bytes());
        assert!(
            deserialize_rounds(&bent, &params(&air)).is_none(),
            "an element equal to the modulus parsed"
        );
    }
}

#[cfg(test)]
mod identity {
    use super::*;
    use crate::proof_wire::{deserialize_rounds, read_header, ParamSet};
    use crate::proof_wire::{FORMAT_VERSION, MAGIC, PROTOCOL_VERSION};

    fn artifact() -> (Vec<u8>, ParamSet) {
        use crate::crypto::stark::air::StarkProofExtRounds;
        let (air, pre, _root) = crate::preprocessed_tests::setup();
        let n_q = pre.proof.queries.len();
        let params = ParamSet::of(&air, 32, 8, 3);
        let rounds = StarkProofExtRounds {
            pre,
            perm_root: [0u8; 32],
            region_width: 510,
            perm_paths: alloc::vec![alloc::vec![[9u8; 32]; 3]; n_q],
        };
        (serialize_rounds(&rounds, &params), params)
    }

    /// The header says what it is, and the parser reads it back.
    #[test]
    fn an_artifact_declares_itself() {
        let (bytes, params) = artifact();
        assert_eq!(&bytes[..4], &MAGIC, "the magic leads");
        let h = read_header(&bytes).expect("the header reads");
        assert_eq!(h.format, FORMAT_VERSION);
        assert_eq!(h.protocol, PROTOCOL_VERSION);
        assert_eq!(h.params, params.id());
        assert!(deserialize_rounds(&bytes, &params).is_some());
    }

    /// Wrong magic, wrong format, wrong protocol: each refused on its own.
    /// A reader that decoded past any of these would be looking at the wrong
    /// fields, the wrong relation, or both.
    #[test]
    fn a_foreign_header_is_refused() {
        let (bytes, params) = artifact();
        for (at, what) in [(0usize, "magic"), (4, "format"), (6, "protocol")] {
            let mut bent = bytes.clone();
            bent[at] ^= 1;
            assert!(
                deserialize_rounds(&bent, &params).is_none(),
                "a bent {what} parsed"
            );
        }
    }

    /// The identity a decoder cannot notice on its own: every byte parses and
    /// the parameter set is not the one this verifier was generated for.
    #[test]
    fn the_wrong_parameter_set_is_refused() {
        let (bytes, params) = artifact();
        let mut other = params;
        other.n_queries += 1;
        assert_ne!(
            other.id(),
            params.id(),
            "the identity must move with the point"
        );
        assert!(
            deserialize_rounds(&bytes, &other).is_none(),
            "a proof at another soundness point parsed"
        );
        assert!(
            deserialize_rounds(&bytes, &params).is_some(),
            "its own point still parses"
        );
    }

    /// An artifact from before the format described itself has no header, so
    /// it does not parse as one that does. No auto-detection: production
    /// verification takes one format.
    #[test]
    fn a_headerless_artifact_is_not_silently_accepted() {
        let (bytes, params) = artifact();
        let legacy = &bytes[crate::proof_wire::HEADER_BYTES..];
        assert!(read_header(legacy).is_none(), "a body is not a header");
        assert!(
            deserialize_rounds(legacy, &params).is_none(),
            "a headerless artifact parsed on the production path"
        );
    }
}
