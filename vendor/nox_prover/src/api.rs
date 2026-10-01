// NONOS Operating System (AGPL-3.0-or-later)
//! The prover as a wallet links it: typed errors, progress, cancellation,
//! and verification against the launch circuit's pinned periodic root.
//!
//! ```text
//! let cancel = AtomicBool::new(false);
//! let opts = Options { cache: Some(&bundled_cache), progress: Some(&|p, f| ui(p, f)), cancel: Some(&cancel) };
//! let (proof, publics) = prove_with(&request, &seed, &entropy, &opts)?;
//! verify(&proof.bytes, &publics, &bundled_cache)?;
//! ```
//!
//! Progress and cancellation act between the prover's phases. A phase runs
//! to its end once started; the longest, FRI with its grinds, is a few tens
//! of seconds on a phone.

use crate::{policy, Proof, Rank, PERIODIC_CUT};
use core::sync::atomic::{AtomicBool, Ordering};
use stark_proofs::crypto::stark::air::{
    domain_params_blown, share_paths, stark_verify_ext_rounds_positions,
    stark_verify_ext_rounds_shared_why, WiredMultiGen,
};
use stark_proofs::crypto::stark::air::{
    stark_prove_ext_rounds, stark_prove_ext_rounds_top_observed, stark_verify_ext_rounds_why,
};
use stark_proofs::crypto::stark::field::{Fp, P};
use stark_proofs::crypto::stark::fri::FRI_FOLD_LOG;
use stark_proofs::crypto::stark::merkle::{TreeTop, DIGEST_BYTES};
use stark_proofs::host::{build_parts_with, Entropy};
use stark_proofs::proof_wire::{
    deserialize_rounds, deserialize_rounds_shared, serialize_rounds, serialize_rounds_shared,
    ParamSet,
};
use stark_proofs::recursion_assembly::inner::{hasher, hide_at};
use stark_proofs::shield::batch::assemble;
use stark_proofs::shield::join::publics::WORDS;
use stark_proofs::shield::join::{join_split_shape, JoinSplit};
use stark_proofs::shield::member::TREE_DEPTH;
use stark_proofs::shield_params::direct;
use stark_proofs::zk_rank::check_fri_rank;

/// The launch circuit's periodic root, the 24 bytes every verifier holds. A
/// cache whose root is anything else is refused before it is used.
#[cfg(all(feature = "launch_v1", not(feature = "digest32")))]
pub const PERIODIC_ROOT: [u8; DIGEST_BYTES] = [
    0xbb, 0x76, 0x14, 0x93, 0x7a, 0xe6, 0xd7, 0xe5, 0xe2, 0x6e, 0x88, 0x61, 0x0f, 0xae, 0x8f, 0xf9,
    0xe5, 0x19, 0x5f, 0xef, 0x47, 0x21, 0xfd, 0xbd,
];

/// The v1.1 circuit's periodic root: the launch program with the checkpoint
/// rule. Its periodic tree carries one selector column more per membership and
/// chain kind, so the root moves.
#[cfg(all(not(feature = "launch_v1"), not(feature = "digest32")))]
pub const PERIODIC_ROOT: [u8; DIGEST_BYTES] = [
    0x76, 0x10, 0xe7, 0x59, 0x93, 0xc1, 0xde, 0x7b, 0x8d, 0xa0, 0x7a, 0x5c, 0xa6, 0x92, 0x0f, 0x0e,
    0x66, 0xcd, 0xb8, 0x8d, 0x6a, 0x43, 0x3e, 0x23,
];

/// The v2 circuit's periodic root (spec/v2/MANIFEST.md): overlay, checkpoint
/// rule, 32-byte digests, radix 8.
#[cfg(all(feature = "digest32", feature = "v2"))]
pub const PERIODIC_ROOT: [u8; DIGEST_BYTES] = [
    0x89, 0x8b, 0x80, 0x0f, 0x60, 0xf4, 0x67, 0xf0, 0x4a, 0xc9, 0x14, 0x0f, 0xb4, 0x25, 0xcd, 0x54,
    0x18, 0x1e, 0x4d, 0x16, 0x42, 0xf6, 0x1f, 0xc3, 0x8b, 0x59, 0x65, 0xd0, 0x8a, 0xce, 0x28, 0x88,
];

/// 32-byte digests without the v2 circuit is no shipped circuit: no cache has
/// an all-zero root, so every cache is refused. Fail closed, not open.
#[cfg(all(feature = "digest32", not(feature = "v2")))]
pub const PERIODIC_ROOT: [u8; DIGEST_BYTES] = [0u8; DIGEST_BYTES];

/// Why a proof was not made or not accepted. Every refusal is one of these;
/// nothing in this crate panics on its input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The request or the seed file is malformed or inconsistent.
    Request(String),
    /// The request breaks an anonymity default and does not opt out of it.
    Policy(String),
    /// The entropy ran out: pass `ENTROPY_BYTES` fresh bytes.
    Entropy(String),
    /// The periodic cache is malformed or belongs to another circuit.
    Cache(String),
    /// The circuit refused the witness: a spend that cannot be proved.
    Circuit(String),
    /// A proof failed verification. From `prove_with` this means nothing
    /// was returned; from `verify`, the proof is not accepted.
    NotVerified(String),
    /// The proof verified but the zero-knowledge rank condition was not
    /// certified for it (docs/12-zero-knowledge.md, Section 4.4). Nothing was
    /// returned: prove again with fresh entropy. About one proof in 2,044.
    Rank(String),
    /// The caller cancelled between phases.
    Cancelled,
}

impl Error {
    /// A stable number per kind, the one the C and wallet interfaces return.
    /// Never renumber: a wallet maps these one to one to what it shows. 8 is the
    /// C interface's null-pointer code, which has no `Error` of its own.
    pub const fn code(&self) -> i32 {
        match self {
            Error::Request(_) => 1,
            Error::Policy(_) => 2,
            Error::Entropy(_) => 3,
            Error::Cache(_) => 4,
            Error::Circuit(_) => 5,
            Error::NotVerified(_) => 6,
            Error::Cancelled => 7,
            Error::Rank(_) => 9,
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Request(s) => write!(f, "request: {s}"),
            Error::Policy(s) => write!(f, "anonymity default: {s}"),
            Error::Entropy(s) => write!(f, "entropy: {s}"),
            Error::Cache(s) => write!(f, "periodic cache: {s}"),
            Error::Circuit(s) => write!(f, "circuit: {s}"),
            Error::NotVerified(s) => write!(f, "not verified: {s}"),
            Error::Rank(s) => write!(f, "rank condition: {s}"),
            Error::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl std::error::Error for Error {}

/// The phases a proof reports, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Request,
    Blinding,
    Region,
    Products,
    Periodic,
    Composition,
    CompositionTree,
    Deep,
    Fri,
    Queries,
    Verified,
}

impl Phase {
    /// The phase the prover reports under `name`, and how far through the
    /// whole proof it ends, from measured phase times on eight cores.
    fn of(name: &str) -> Option<(Phase, f32)> {
        Some(match name {
            "region committed" => (Phase::Region, 0.14),
            "products committed" => (Phase::Products, 0.22),
            "periodic" => (Phase::Periodic, 0.24),
            "composition" => (Phase::Composition, 0.42),
            "composition tree" => (Phase::CompositionTree, 0.46),
            "deep" => (Phase::Deep, 0.55),
            "fri" => (Phase::Fri, 0.93),
            "queries" => (Phase::Queries, 0.96),
            _ => return None,
        })
    }
}

/// What a caller may pass besides the request, the seed and the entropy.
#[derive(Default)]
pub struct Options<'a> {
    /// The periodic cache the app bundles. Without it the tree is rebuilt,
    /// a quarter more time and half a gigabyte more memory.
    pub cache: Option<&'a [u8]>,
    /// Called at every phase boundary with the phase just finished and the
    /// fraction of the proof done.
    pub progress: Option<&'a (dyn Fn(Phase, f32) + Sync)>,
    /// Set to stop the proof at the next phase boundary.
    pub cancel: Option<&'a AtomicBool>,
}

impl Options<'_> {
    fn report(&self, p: Phase, f: f32) {
        if let Some(cb) = self.progress {
            cb(p, f);
        }
    }

    fn cancelled(&self) -> bool {
        self.cancel
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(false)
    }
}

/// A cache from bytes, refused unless its root is the launch circuit's.
pub fn load_cache(bytes: &[u8]) -> Result<TreeTop, Error> {
    let top = TreeTop::from_bytes(bytes).ok_or_else(|| Error::Cache("malformed".into()))?;
    if top.root()[..DIGEST_BYTES] != PERIODIC_ROOT {
        return Err(Error::Cache(
            "its root is not the launch circuit's periodic root".into(),
        ));
    }
    Ok(top)
}

/// Prove a spend, with progress and cancellation. Returns the proof and its
/// 36 public words. The proof is verified before it is returned.
pub fn prove_with(
    request: &str,
    seed: &str,
    entropy: &[u8],
    opts: &Options<'_>,
) -> Result<(Proof, [u64; WORDS]), Error> {
    let top = opts.cache.map(load_cache).transpose()?;
    let (proof, _) = prove_inner(request, seed, entropy, top.as_ref(), opts)?;
    let publics: [u64; WORDS] = proof
        .publics
        .clone()
        .try_into()
        .map_err(|_| Error::Circuit("the statement is not 36 words".into()))?;
    Ok((proof, publics))
}

/// Verify a proof against its 36 public words, with the periodic root taken
/// from the cache after it is checked against `PERIODIC_ROOT`.
pub fn verify(proof: &[u8], publics: &[u64], cache: &[u8]) -> Result<(), Error> {
    let top = load_cache(cache)?;
    let (q, grind) = point_of(proof, publics)?;
    let (words, air, params) = statement_at(publics, q, grind)?;
    let extra = direct::EXTRA_BLOWUP_BITS;
    let rounds = deserialize_rounds(proof, &params).ok_or_else(|| {
        Error::NotVerified("not a proof at the launch point for this circuit".into())
    })?;
    stark_verify_ext_rounds_why(air, &rounds, q, grind, extra, &top.root(), &words)
        .map_err(|why| Error::NotVerified(why.to_string()))
}

/// The statement 36 public words name: the words as field elements, the
/// launch circuit over them, and its parameter set. Refuses a count other
/// than 36 and a word at or above p.
fn statement(publics: &[u64]) -> Result<(Vec<Fp>, WiredMultiGen, ParamSet), Error> {
    statement_at(publics, direct::N_QUERIES, direct::GRIND_BITS)
}

/// The query point a proof's header names. On v1 there is one, the launch
/// point. On v2 the header's parameter identity must be one of the accepted
/// shapes' identities over this statement's circuit; the shape's query count
/// and grind are then this verifier's own constants for that identity, never
/// numbers read from the proof.
fn point_of(proof: &[u8], publics: &[u64]) -> Result<(usize, u32), Error> {
    #[cfg(feature = "v2")]
    {
        let (_, air, _) = statement(publics)?;
        let h = stark_proofs::proof_wire::read_header(proof)
            .ok_or_else(|| Error::NotVerified("no header".into()))?;
        for (_, q, g) in stark_proofs::crypto::stark::fri_ext::V2_SHAPES {
            if ParamSet::of(&air, q, g, direct::EXTRA_BLOWUP_BITS).id() == h.params {
                return Ok((q, g));
            }
        }
        Err(Error::NotVerified(
            "the header names no accepted v2 shape".into(),
        ))
    }
    #[cfg(not(feature = "v2"))]
    {
        let _ = (proof, publics);
        Ok((direct::N_QUERIES, direct::GRIND_BITS))
    }
}

fn statement_at(
    publics: &[u64],
    q: usize,
    grind: u32,
) -> Result<(Vec<Fp>, WiredMultiGen, ParamSet), Error> {
    if publics.len() != WORDS {
        return Err(Error::Request(format!(
            "{} public words, not {WORDS}",
            publics.len()
        )));
    }
    if publics.iter().any(|&v| v >= P) {
        return Err(Error::Request("a public word is not below p".into()));
    }
    let words: Vec<Fp> = publics.iter().map(|&v| Fp::from_u64(v)).collect();
    let air = join_split_shape(TREE_DEPTH, &words);
    let params = ParamSet::of(&air, q, grind, direct::EXTRA_BLOWUP_BITS);
    Ok((words, air, params))
}

/// A launch proof re-encoded as format 6, its paths shared
/// (docs/14-shared-paths.md). The proof is verified first, which is what
/// yields the positions the streams are ordered by; a proof that does not
/// verify is not re-encoded.
pub fn to_shared(proof: &[u8], publics: &[u64], cache: &[u8]) -> Result<Vec<u8>, Error> {
    share_under(proof, publics, &load_cache(cache)?.root())
}

/// Verify a format 6 proof against its 36 public words.
pub fn verify_shared(proof: &[u8], publics: &[u64], cache: &[u8]) -> Result<(), Error> {
    verify_shared_under(proof, publics, &load_cache(cache)?.root())
}

pub(crate) fn share_under(
    proof: &[u8],
    publics: &[u64],
    root: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    let (q, grind) = point_of(proof, publics)?;
    let (words, air, params) = statement_at(publics, q, grind)?;
    let extra = direct::EXTRA_BLOWUP_BITS;
    let log_n = domain_params_blown(&air, extra).0;
    let rounds = deserialize_rounds(proof, &params).ok_or_else(|| {
        Error::NotVerified("not a proof at the launch point for this circuit".into())
    })?;
    let positions = stark_verify_ext_rounds_positions(air, &rounds, q, grind, extra, root, &words)
        .map_err(|why| Error::NotVerified(why.to_string()))?;
    let shared = share_paths(&rounds, &positions, log_n)
        .ok_or_else(|| Error::NotVerified("the proof's paths do not share".into()))?;
    Ok(serialize_rounds_shared(&rounds, &shared, &params))
}

pub(crate) fn verify_shared_under(
    proof: &[u8],
    publics: &[u64],
    root: &[u8; 32],
) -> Result<(), Error> {
    let (q, grind) = point_of(proof, publics)?;
    let (words, air, params) = statement_at(publics, q, grind)?;
    let extra = direct::EXTRA_BLOWUP_BITS;
    let (skeleton, shared) = deserialize_rounds_shared(proof, &params).ok_or_else(|| {
        Error::NotVerified("not a format 6 proof at the launch point for this circuit".into())
    })?;
    stark_verify_ext_rounds_shared_why(air, &skeleton, &shared, q, grind, extra, root, &words)
        .map_err(|why| Error::NotVerified(why.to_string()))
}

pub(crate) fn prove_inner(
    request: &str,
    seed: &str,
    entropy: &[u8],
    top: Option<&TreeTop>,
    opts: &Options<'_>,
) -> Result<(Proof, Vec<u8>), Error> {
    let weakened = policy::check(request, &policy::own_keys(seed)).map_err(Error::Policy)?;
    let (q, grind, extra) = (
        direct::N_QUERIES,
        direct::GRIND_BITS,
        direct::EXTRA_BLOWUP_BITS,
    );
    // Every random value below is drawn from the hedged stream, never from the
    // caller's bytes alone: reused bytes under another spend stay safe.
    let stream = crate::hedge::hedge(entropy, seed, request).map_err(Error::Entropy)?;
    let mut e = Entropy::new(&stream);
    let (parts, created) = {
        let mut words = |n: usize| e.words(n);
        build_parts_with(request, seed, &mut words).map_err(Error::Request)?
    };
    let mut b = assemble(vec![parts.parts]);
    let intent = b
        .intents
        .pop()
        .ok_or_else(|| Error::Circuit("the spend assembled no statement".into()))?;
    let mut js = JoinSplit {
        wired: b.wired,
        witness: b.witness,
        intent,
    };
    opts.report(Phase::Request, 0.03);
    if opts.cancelled() {
        return Err(Error::Cancelled);
    }

    let h = hasher();
    let w = e.words(4).map_err(Error::Entropy)?;
    let s: [Fp; 4] = [w[0], w[1], w[2], w[3]];
    let blind = hide_at(&h, &mut js, &s, q, 1usize << FRI_FOLD_LOG);
    let params = ParamSet::of(&js.wired, q, grind, extra);
    let publics = js.intent.clone();
    let mut witness = js.witness;
    opts.report(Phase::Blinding, 0.05);

    let observe = |name: &'static str| -> bool {
        if let Some((p, f)) = Phase::of(name) {
            opts.report(p, f);
        }
        !opts.cancelled()
    };
    let (rounds, air, root, cache) = match top {
        Some(top) => {
            let proved = stark_prove_ext_rounds_top_observed(
                js.wired,
                &mut witness,
                q,
                grind,
                extra,
                &publics,
                top,
                &blind,
                &observe,
            );
            let Some((rounds, air)) = proved else {
                return Err(if opts.cancelled() {
                    Error::Cancelled
                } else {
                    Error::Cache("the periodic cache is not this circuit's".into())
                });
            };
            (rounds, air, top.root(), Vec::new())
        }
        None => {
            let (rounds, tree, air) = stark_prove_ext_rounds(
                js.wired,
                &mut witness,
                q,
                grind,
                extra,
                &publics,
                None,
                &blind,
            )
            .ok_or_else(|| {
                Error::Circuit(
                    "the circuit carries no permutation columns above its regions".into(),
                )
            })?;
            let cache = TreeTop::of(&tree, PERIODIC_CUT)
                .map(|t| t.to_bytes())
                .unwrap_or_default();
            (rounds, air, tree.root(), cache)
        }
    };
    drop(witness);
    stark_verify_ext_rounds_why(air, &rounds, q, grind, extra, &root, &publics).map_err(|why| {
        Error::NotVerified(format!(
            "the proof does not verify, nothing returned: {why}"
        ))
    })?;
    opts.report(Phase::Verified, 1.0);
    let fri = &rounds.pre.proof.fri;
    let grind_hashes = fri
        .pow_chain
        .iter()
        .chain(&fri.fold_nonces)
        .fold(fri.pow_nonce, |a, n| a.saturating_add(*n));
    let bytes = serialize_rounds(&rounds, &params);
    let words: Vec<u64> = publics.iter().map(|v| v.to_u64()).collect();
    /*
     * The rank condition on the bytes that leave, before they leave. A proof
     * is returned only with a certificate beside it; a shortfall returns
     * nothing and the caller proves again with fresh entropy.
     */
    let r = check_fri_rank(&bytes, &words, 3).map_err(Error::NotVerified)?;
    if !r.holds {
        return Err(Error::Rank(format!(
            "{} of {} certified after {} subsets; prove again with fresh entropy",
            r.mask_rank, r.bound, r.attempts
        )));
    }
    let proof = Proof {
        weakened,
        grind_hashes,
        rank: Rank {
            bound: r.bound,
            certified: r.mask_rank,
            subsets: r.attempts,
        },
        bytes,
        publics: words,
        created,
    };
    Ok((proof, cache))
}

/// Decide the zero-knowledge rank condition (R) for a proof before it is
/// sent (docs/12-zero-knowledge.md Section 4.4): `Ok` when it holds, which makes
/// the proof exactly simulatable beyond FRI layer zero. A wallet runs this on
/// every proof until the condition is a theorem.
pub fn zk_fri_rank_check(proof: &[u8], publics: &[u64]) -> Result<(), Error> {
    let r = stark_proofs::zk_rank::check_fri_rank(proof, publics, 3).map_err(Error::NotVerified)?;
    if r.holds {
        Ok(())
    } else {
        Err(Error::NotVerified(format!(
            "the rank condition was not certified: {} of {} after {} subsets",
            r.mask_rank, r.bound, r.attempts
        )))
    }
}
