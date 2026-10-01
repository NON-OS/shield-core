// NONOS Operating System (AGPL-3.0-or-later)
//! The spend as a caller holds it, and the plain calls that make one.

use crate::api::{self, load_cache, Options};
use stark_proofs::crypto::stark::merkle::TreeTop;
use stark_proofs::host::{pack_u256, quad, Created};
use stark_proofs::shield::note::note_parts;
use stark_proofs::shield_params::direct;

/// Random bytes a caller passes: enough for the created notes' secrets and
/// blindings and the proof's blinding seed, with room for rejected draws.
pub const ENTROPY_BYTES: usize = 512;

/// The query grind's bits at the launch point, for a caller reading
/// `Proof::grind_hashes` against its mean.
pub const GRIND_BITS: u32 = direct::GRIND_BITS;

/// Levels of the periodic tree a cache leaves out: each opening recomputes
/// `2^PERIODIC_CUT` leaves. At 6 the cache is 1/64 of the tree, about 8 MB.
pub const PERIODIC_CUT: usize = 6;

/// A proved spend.
pub struct Proof {
    /// The proof in the format five codec, as the chain reads it.
    pub bytes: Vec<u8>,
    /// The statement: 36 public words, in the order the pool reads them.
    pub publics: Vec<u64>,
    /// The notes the spend creates. The spender's secrets are here and
    /// nowhere else: the caller keeps them.
    pub created: Created,
    /// The grinds' winning nonces added up: about how many hashes the proof
    /// of work took. The search takes the smallest nonce that wins, so the
    /// nonce is the attempts, and the attempts are luck: their mean is
    /// `2^GRIND_BITS` and their spread about as large. A timing read without
    /// this number says as much about the dice as about the prover.
    pub grind_hashes: u64,
    /// The anonymity defaults this request opted out of, by name (`policy`).
    /// Empty when it kept them all.
    pub weakened: Vec<&'static str>,
    /// The zero-knowledge rank certificate this proof passed before it was
    /// returned. A relayer that wants its own evidence recomputes it from
    /// the bytes with `zk_fri_rank_check`: it needs nothing secret.
    pub rank: Rank,
}

/// A rank certificate: the free values FRI reveals beyond layer zero
/// (`bound`), how many the masks reached (`certified`, equal to `bound` on
/// every returned proof) and how many sampled subsets it took.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rank {
    pub bound: usize,
    pub certified: usize,
    pub subsets: usize,
}

/// Prove a spend of the notes in `seed` against the pool state in `request`,
/// building the periodic tree from scratch: a quarter of the time on one
/// thread. `prove_with_cache` skips it.
pub fn prove(request: &str, seed: &str, entropy: &[u8]) -> Result<Proof, String> {
    prove_keeping_cache(request, seed, entropy).map(|(p, _)| p)
}

/// `prove`, also returning the periodic cache (`TreeTop` bytes) the full
/// tree yields for free. The cache is the same for every spend: an app stores
/// it once, or ships it, and hands it to `prove_with_cache` from then on.
pub fn prove_keeping_cache(request: &str, seed: &str, entropy: &[u8]) -> Result<(Proof, Vec<u8>), String> {
    prove_from(request, seed, entropy, None)
}

/// `prove` from a periodic cache. The cache is untrusted input: every chunk
/// an opening recomputes must hash to the node stored above it, and the
/// proof must verify against the root the cache claims, so a wrong cache
/// yields an error, never a proof the chain refuses.
pub fn prove_with_cache(request: &str, seed: &str, entropy: &[u8], cache: &[u8]) -> Result<Proof, String> {
    let top = load_cache(cache).map_err(|e| e.to_string())?;
    prove_from(request, seed, entropy, Some(&top)).map(|(p, _)| p)
}

fn prove_from(request: &str, seed: &str, entropy: &[u8], top: Option<&TreeTop>) -> Result<(Proof, Vec<u8>), String> {
    api::prove_inner(request, seed, entropy, top, &Options::default()).map_err(|e| e.to_string())
}

/// A proof as one JSON object: the proof as hex, the public words, and the
/// created notes with their leaves. The secrets of the notes the spender owns
/// are in it, so the caller treats the whole object as a secret.
pub fn to_json(p: &Proof) -> String {
    let hex: String = p.bytes.iter().map(|b| format!("{b:02x}")).collect();
    let words: Vec<String> = p.publics.iter().map(u64::to_string).collect();
    let notes: Vec<String> = (0..2)
        .map(|i| {
            let n = &p.created.notes[i];
            let secret = if p.created.owned[i] {
                format!("{:?}", quad(&p.created.secrets[i * 4..(i + 1) * 4]))
            } else {
                "null".to_string()
            };
            format!(
                "{{\"leaf\": \"{}\", \"value\": {}, \"asset_id\": {}, \"spend_pk\": {:?}, \"blinding\": {:?}, \
                 \"owned\": {}, \"secret\": {secret}}}",
                pack_u256(&note_parts(n).cm),
                n.value,
                n.asset_id,
                n.spend_pk,
                n.blinding,
                p.created.owned[i]
            )
        })
        .collect();
    format!(
        "{{\"point\": [{}, {}, {}], \"proof\": \"0x{hex}\", \"proof_bytes\": {}, \"grind_hashes\": {}, \
         \"rank\": {{\"bound\": {}, \"certified\": {}, \"subsets\": {}}}, \"weakened\": [{}], \"publics\": [{}], \"outputs\": [{}]}}",
        direct::N_QUERIES,
        direct::GRIND_BITS,
        direct::EXTRA_BLOWUP_BITS,
        p.bytes.len(),
        p.grind_hashes,
        p.rank.bound,
        p.rank.certified,
        p.rank.subsets,
        p.weakened.iter().map(|w| format!("\"{w}\"")).collect::<Vec<_>>().join(", "),
        words.join(", "),
        notes.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{verify, Error};
    use stark_proofs::host::Entropy;

    /// A cache that is not the launch circuit's is refused by name, before
    /// anything is proved.
    #[test]
    fn a_foreign_cache_is_refused() {
        assert!(matches!(load_cache(b"NXTT"), Err(Error::Cache(_))));
        let why = verify(&[], &[0; 36], b"garbage").err();
        assert!(matches!(why, Some(Error::Cache(_))), "{why:?}");
    }

    /// A bad request is refused as a request or policy error, whatever
    /// else was set; cancellation is exercised on a real spend by
    /// `nox_api_check`.
    #[test]
    fn a_bad_request_is_refused_by_kind() {
        let flag = core::sync::atomic::AtomicBool::new(true);
        let opts = Options { cancel: Some(&flag), ..Default::default() };
        let r = api::prove_inner("{}", "{}", &[7u8; ENTROPY_BYTES], None, &opts);
        assert!(matches!(r, Err(Error::Policy(_)) | Err(Error::Request(_))), "a bad request is refused first");
    }

    /// A malformed request or seed comes back as a reason. A library that
    /// ended the process on bad input would take the host app with it.
    #[test]
    fn bad_input_is_an_error_not_an_exit() {
        let entropy = [7u8; ENTROPY_BYTES];
        let why = prove("{}", "{}", &entropy).err().unwrap_or_default();
        assert!(why.contains("request lacks"), "a request with no fields was not refused by name: {why}");
        let why = prove("not json at all", "", &entropy).err().unwrap_or_default();
        assert!(!why.is_empty(), "garbage was accepted");
    }

    /// Garbage in place of a cache is refused before any proving starts.
    #[test]
    fn a_malformed_cache_is_refused() {
        let why = prove_with_cache("{}", "{}", &[7u8; ENTROPY_BYTES], b"NXTTnope").err().unwrap_or_default();
        assert!(why.contains("periodic cache: malformed"), "a malformed cache got through: {why}");
    }

    /// Entropy is refused when it runs out, never stretched or reused.
    #[test]
    fn short_entropy_is_refused() {
        let mut e = Entropy::new(&[1u8; 15]);
        assert!(e.words(1).is_ok(), "eight bytes make one word");
        assert!(e.words(1).is_err(), "seven bytes were stretched into a word");
    }
}
