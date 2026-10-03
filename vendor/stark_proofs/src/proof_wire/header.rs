// NONOS Operating System (AGPL-3.0-or-later)
//! What an artifact says it is, before anything reads what it contains.
//!
//! The format carried no self-description until 2026-09-22. A radix-two file
//! and a radix-four file were byte-indistinguishable at the head, and what
//! caught the one mismatch that mattered was `regionWidth` decoding as
//! 3,522,111,791 instead of 590: a plausibility value doing a version's job,
//! which worked twice and is not a mechanism.
//!
//! Three identities, because they answer three different questions and a
//! reader that conflates them will accept a proof it can decode and must not
//! believe:
//!
//!   `format` says how the bytes decode: section order, digest width, how
//!   many values a FRI layer carries. Wrong format, and the reader is
//!   looking at the wrong fields.
//!
//!   `protocol` says what the decoded statement means. Same bytes, different
//!   relation, is a proof of something else.
//!
//!   `params` says which configuration produced it: the queries, the rate,
//!   the grind, the fold, the shape. A correctly decoded proof of the right
//!   relation at the wrong soundness point is the failure this one exists to
//!   stop, and it is the only one of the three that a decoder cannot notice
//!   on its own.

use crate::crypto::stark::hash::keccak256;
use alloc::vec::Vec;

/// Four bytes that are not a field element, a length, or a digest, so a file
/// that is not one of ours fails on its first word rather than its fourth
/// section.
pub const MAGIC: [u8; 4] = *b"NOXP";

/// How the bytes decode. Moves when the wire layout moves: the digest width,
/// the fold radix, the section order, the encoding of any field.
///
/// 4: the consistency query's DEEP value opens in FRI layer zero, with the
/// other three values of its leaf and a path two levels shorter.
///
/// 5: the consistency check runs at FRI's positions, drawn after the nonce
/// from a FRI transcript seeded by the STARK's, and reads its DEEP value from
/// FRI's own layer-zero opening. The DEEP root and the per-query DEEP opening
/// leave the wire.
pub const FORMAT_VERSION: u16 = 5;

/// 6: format 5 with every Merkle path shared. Each tree carries one sibling
/// stream for all its queries (`merkle::multi`) in place of a path per query,
/// and the streams follow the rest of the body. Same statement, same
/// parameter identity: only the encoding moves, which is what this number is.
pub const FORMAT_SHARED: u16 = 6;

/// 7: format 6 on the format 7 transcript (docs/17): FOLD = 8 values a FRI layer,
/// the DEEP nonce right after the periodic claims at z, three fold nonces,
/// eight query nonces, 32-byte digests. The `fri8` build writes and reads only
/// this for shared-path artifacts.
pub const FORMAT_7: u16 = 7;

/// The shared-path format this build writes and reads.
#[cfg(not(feature = "fri8"))]
pub const FORMAT_SHARED_BUILD: u16 = FORMAT_SHARED;
#[cfg(feature = "fri8")]
pub const FORMAT_SHARED_BUILD: u16 = FORMAT_7;

/// The transcript version a format 7 identity records.
pub const TRANSCRIPT_PROTOCOL: u32 = 2;

/// The draw rule a format 7 identity records: 1, exact streams (docs/15).
pub const DRAW_RULE_EXACT: u32 = 1;

/// What the decoded statement means. Moves when the relation moves, which is
/// not the same event and must not share a number with it.
pub const PROTOCOL_VERSION: u16 = 1;

/// The bytes a header occupies.
pub const HEADER_BYTES: usize = 4 + 2 + 2 + 32;

/// What the parameter identity is a hash of. A bare hash over ten integers is
/// a hash any other protocol can also produce from ten integers, and an
/// identity that collides across protocols is not an identity. The tag moves
/// with the encoding of the set, not with the values in it.
pub const PARAMS_DOMAIN: &[u8] = b"NOX_PARAMS_V1";

/// An artifact's self-description.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Header {
    pub format: u16,
    pub protocol: u16,
    pub params: [u8; 32],
}

/// The configuration a proof was produced under, in the order the identity
/// hashes them. Every field is one a verifier holds as a deployment constant,
/// so both sides compute the same identity from their own constants and
/// neither takes it from the proof.
///
/// The rule this set is under: a value that can change soundness, or change
/// what a correctly decoded proof means, must change the identity. Leaving a
/// security parameter outside it is a release blocker, and
/// `every_field_moves_the_identity` is the gate that says so.
///
/// Two classes are deliberately absent, and only these two:
///
///   Build constants that cannot vary within an implementation: the field
///   modulus, the extension polynomial, the Merkle hash. A build that changes
///   one of them is a different verifier, not a different parameter set, and
///   `format` is where that disagreement surfaces.
///
///   Values already bound by the baked periodic root, which the verifier
///   holds as an immutable and every proof is checked against: the circuit's
///   round constants, the inner sponge's round count, the relation's wiring.
///   A proof at a different one of those fails against the root it is
///   verified under, before the identity is consulted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ParamSet {
    pub n_queries: u32,
    pub grind_bits: u32,
    pub extra_blowup_bits: u32,
    pub fri_fold_log: u32,
    pub fri_stop_log: u32,
    pub digest_bytes: u32,
    pub trace_width: u32,
    pub n_periodic: u32,
    pub log_trace_len: u32,
    pub constraint_degree: u32,
    /// Rows the transition reads at once. Sets the out-of-domain frame's
    /// length, so a reader that disagrees reads the wrong number of elements
    /// and every offset after it.
    pub window_size: u32,
    /// How many transition constraints the composition batches. A verifier
    /// that expects a different count draws a different number of alphas off
    /// the same transcript and diverges from the prover silently.
    pub num_transition: u32,
    /// How many boundary constraints. Same argument, different batch.
    pub n_boundary: u32,
    /// The coset the evaluation domain is shifted onto. Not a size: it is
    /// which points the proof is about, and a verifier checking the right
    /// polynomial on the wrong coset checks nothing.
    pub coset_shift: u64,
    /// Bits of proof-of-work before each FRI folding challenge, and so one
    /// nonce per layer on the wire. Zero on every format five artifact before
    /// it, and hashed into the identity only when nonzero, so their
    /// identities stand.
    pub commit_grind_bits: u32,
    /// How many chained searches the query grind is split into, and so how
    /// many query nonces are on the wire. One on every artifact before the
    /// split, and hashed into the identity only when it is not one.
    pub grind_chunks: u32,
}

impl ParamSet {
    /// The set a proof of `air` at this point was produced under. One
    /// constructor, so the prover, the emitter and the verifier cannot each
    /// assemble a parameter identity their own way.
    pub fn of<A: crate::crypto::stark::air::AirExt>(
        air: &A,
        n_queries: usize,
        grind_bits: u32,
        extra_blowup_bits: u32,
    ) -> ParamSet {
        ParamSet {
            n_queries: n_queries as u32,
            grind_bits,
            extra_blowup_bits,
            fri_fold_log: crate::crypto::stark::fri::FRI_FOLD_LOG,
            fri_stop_log: crate::crypto::stark::fri::FRI_STOP_LOG,
            digest_bytes: crate::crypto::stark::merkle::DIGEST_BYTES as u32,
            trace_width: air.trace_width() as u32,
            n_periodic: air.periodic_count() as u32,
            log_trace_len: air.log_trace_len(),
            constraint_degree: air.constraint_degree() as u32,
            window_size: air.window_size() as u32,
            num_transition: air.num_transition() as u32,
            n_boundary: air.boundary().len() as u32,
            coset_shift: crate::crypto::stark::air::COSET_SHIFT,
            commit_grind_bits: crate::crypto::stark::air::replay_pre::commit_grind_bits(
                air.challenge_lanes(),
            ),
            grind_chunks: crate::crypto::stark::air::replay_pre::grind_chunks(
                air.challenge_lanes(),
            ),
        }
    }

    /// The identity: keccak over the domain tag, then the fields in
    /// declaration order, the u32s as four little endian bytes each and the
    /// coset shift as eight. One encoding, one hash, no room for a second
    /// opinion about what a parameter set is.
    pub fn id(&self) -> [u8; 32] {
        keccak256(&self.preimage())
    }

    /// The bytes the identity hashes, exposed so a test can ask what the tag
    /// is worth and a port can check its own encoding against this one rather
    /// than against a digest it cannot take apart.
    pub fn preimage(&self) -> Vec<u8> {
        let f = [
            self.n_queries,
            self.grind_bits,
            self.extra_blowup_bits,
            self.fri_fold_log,
            self.fri_stop_log,
            self.digest_bytes,
            self.trace_width,
            self.n_periodic,
            self.log_trace_len,
            self.constraint_degree,
            self.window_size,
            self.num_transition,
            self.n_boundary,
        ];
        let mut buf = Vec::with_capacity(PARAMS_DOMAIN.len() + 4 * f.len() + 8);
        buf.extend_from_slice(PARAMS_DOMAIN);
        for v in f {
            buf.extend_from_slice(&v.to_le_bytes());
        }
        buf.extend_from_slice(&self.coset_shift.to_le_bytes());
        /*
         * A split grind writes the commit field whatever it holds, then the
         * split. Appending the split alone would let a set with a commit grind
         * of 8 and no split hash the same bytes as one with no commit grind
         * split eight ways.
         */
        if self.grind_chunks != 1 {
            buf.extend_from_slice(&self.commit_grind_bits.to_le_bytes());
            buf.extend_from_slice(&self.grind_chunks.to_le_bytes());
        } else if self.commit_grind_bits != 0 {
            buf.extend_from_slice(&self.commit_grind_bits.to_le_bytes());
        }
        /*
         * Four fields no v1 identity has (docs/17): the transcript
         * version, the DEEP grind, the draw rule and the shape id. So no v1
         * identity equals a format 7 one, and no format 7 shape's equals another's. Only
         * on the launch transcript (the split query grind), the one that runs
         * the DEEP grind and binds a shape: an identity never records a grind
         * its transcript did not run.
         */
        #[cfg(feature = "fri8")]
        if self.grind_chunks > 1 {
            for v in [
                TRANSCRIPT_PROTOCOL,
                crate::crypto::stark::fri_ext::DEEP_GRIND_BITS,
                DRAW_RULE_EXACT,
                crate::crypto::stark::fri_ext::shape_id(self.n_queries as usize) as u32,
            ] {
                buf.extend_from_slice(&v.to_le_bytes());
            }
        }
        buf
    }
}

/// The header bytes for a parameter set, at the current versions.
pub fn write_header(params: &ParamSet) -> Vec<u8> {
    write_header_as(params, FORMAT_VERSION)
}

/// The header bytes for a parameter set at `format`.
pub fn write_header_as(params: &ParamSet, format: u16) -> Vec<u8> {
    let mut b = Vec::with_capacity(HEADER_BYTES);
    b.extend_from_slice(&MAGIC);
    b.extend_from_slice(&format.to_le_bytes());
    b.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    b.extend_from_slice(&params.id());
    b
}

/// Read a header without judging it: what a tool does to an artifact whose
/// provenance it is trying to establish. Production parsing judges.
pub fn read_header(bytes: &[u8]) -> Option<Header> {
    if bytes.len() < HEADER_BYTES || bytes[..4] != MAGIC {
        return None;
    }
    let format = u16::from_le_bytes([bytes[4], bytes[5]]);
    let protocol = u16::from_le_bytes([bytes[6], bytes[7]]);
    let mut params = [0u8; 32];
    params.copy_from_slice(&bytes[8..40]);
    Some(Header {
        format,
        protocol,
        params,
    })
}

/// Read a header and refuse anything this build does not serve. Fail closed:
/// an unknown format is not decoded on the chance it is compatible, and a
/// parameter set this verifier was not generated for is refused even though
/// every byte after it would parse.
pub fn check_header(bytes: &[u8], expect: &ParamSet) -> Option<Header> {
    check_header_as(bytes, expect, FORMAT_VERSION)
}

/// `check_header` for one named format. Each reader names the one it decodes,
/// so no reader decodes a format by accident of it parsing.
pub fn check_header_as(bytes: &[u8], expect: &ParamSet, format: u16) -> Option<Header> {
    let h = read_header(bytes)?;
    if h.format != format || h.protocol != PROTOCOL_VERSION || h.params != expect.id() {
        return None;
    }
    Some(h)
}

/// The identity is only worth what it covers. These two say what it covers,
/// and they are the reason a security parameter cannot quietly leave the set:
/// add a field and forget to hash it, and the first test names it.
#[cfg(test)]
mod identity_covers_what_it_claims {
    use super::*;

    fn base() -> ParamSet {
        ParamSet {
            n_queries: 12,
            grind_bits: 32,
            extra_blowup_bits: 7,
            fri_fold_log: 2,
            fri_stop_log: 8,
            digest_bytes: 24,
            trace_width: 41,
            n_periodic: 119,
            log_trace_len: 17,
            constraint_degree: 8,
            window_size: 2,
            num_transition: 202,
            n_boundary: 3,
            coset_shift: 7,
            commit_grind_bits: 0,
            grind_chunks: 1,
        }
    }

    /// Fourteen mutations, one per field, each the smallest change that field
    /// admits. A field missing from `preimage` shows up here as an identity
    /// that did not move, named.
    #[test]
    fn every_field_moves_the_identity() {
        let id = base().id();
        let mut cases: Vec<(&str, ParamSet)> = Vec::new();
        let mut m = base();
        m.n_queries += 1;
        cases.push(("n_queries", m));
        let mut m = base();
        m.grind_bits += 1;
        cases.push(("grind_bits", m));
        let mut m = base();
        m.extra_blowup_bits += 1;
        cases.push(("extra_blowup_bits", m));
        let mut m = base();
        m.fri_fold_log += 1;
        cases.push(("fri_fold_log", m));
        let mut m = base();
        m.fri_stop_log += 1;
        cases.push(("fri_stop_log", m));
        let mut m = base();
        m.digest_bytes += 1;
        cases.push(("digest_bytes", m));
        let mut m = base();
        m.trace_width += 1;
        cases.push(("trace_width", m));
        let mut m = base();
        m.n_periodic += 1;
        cases.push(("n_periodic", m));
        let mut m = base();
        m.log_trace_len += 1;
        cases.push(("log_trace_len", m));
        let mut m = base();
        m.constraint_degree += 1;
        cases.push(("constraint_degree", m));
        let mut m = base();
        m.window_size += 1;
        cases.push(("window_size", m));
        let mut m = base();
        m.num_transition += 1;
        cases.push(("num_transition", m));
        let mut m = base();
        m.n_boundary += 1;
        cases.push(("n_boundary", m));
        let mut m = base();
        m.coset_shift += 1;
        cases.push(("coset_shift", m));

        assert_eq!(cases.len(), 14, "a field was added without a mutation");
        for (name, m) in cases {
            assert_ne!(
                m.id(),
                id,
                "{name} can change and the parameter identity does not: that is a release blocker"
            );
        }
    }

    /// The tag is in the preimage, at the front, and the digest is not the
    /// digest of the bare fields. An untagged hash over integers is a hash
    /// another protocol can produce by accident.
    #[test]
    fn the_identity_is_domain_separated() {
        let p = base();
        let pre = p.preimage();
        assert_eq!(&pre[..PARAMS_DOMAIN.len()], PARAMS_DOMAIN);
        // Format 7 appends four u32 fields: transcript version, DEEP grind, draw
        // rule and shape id (docs/17).
        let shape_fields = if cfg!(feature = "fri8") && p.grind_chunks > 1 {
            4 * 4
        } else {
            0
        };
        let split = if p.grind_chunks != 1 {
            8
        } else if p.commit_grind_bits != 0 {
            4
        } else {
            0
        };
        assert_eq!(
            pre.len(),
            PARAMS_DOMAIN.len() + 4 * 13 + 8 + split + shape_fields
        );
        let bare = &pre[PARAMS_DOMAIN.len()..];
        assert_ne!(p.id(), keccak256(bare), "the tag is not reaching the hash");
    }
}
