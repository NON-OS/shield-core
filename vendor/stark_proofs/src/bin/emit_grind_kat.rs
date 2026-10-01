// NONOS Operating System (AGPL-3.0-or-later)
//! The split query grind as a known-answer vector: a head, the eight nonces,
//! and the transcript state after each is absorbed, at the launch point.
//!
//!     emit_grind_kat [out.json]
//!
//! The head is the FRI transcript (`NONOS-STARK-FRI-EXT`) after absorbing
//! `keccak256("NOX-GRIND-KAT")` as a digest, standing in for the proof's
//! seed, roots, fold nonces and final layer. From there each grind searches
//! the smallest nonce with `GRIND_BITS - log2(GRIND_CHUNKS)` leading zero bits
//! in the first eight bytes of `keccak256(0x05 || state || nonce le64)` read
//! little endian, then absorbs it: `state = keccak256(0x05 || state || nonce
//! le64)`. A port that reproduces every line reproduces the chain, including
//! that nonce i is searched against the state nonce i-1 left behind.
//!
//! Build with `--features parallel`: eight searches of 2^25 expected hashes.

use stark_proofs::crypto::stark::fri_ext::GRIND_CHUNKS;
use stark_proofs::crypto::stark::hash::keccak256;
use stark_proofs::crypto::stark::transcript::Transcript;
use stark_proofs::shield_params::direct;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let out = std::env::args().nth(1).unwrap_or_else(|| "grind-kat.json".into());
    let per = direct::GRIND_BITS - GRIND_CHUNKS.trailing_zeros();

    let mut t = Transcript::new(b"NONOS-STARK-FRI-EXT");
    t.absorb_digest(&keccak256(b"NOX-GRIND-KAT"));
    let head = t.state();

    let mut rows = Vec::new();
    for i in 0..GRIND_CHUNKS {
        let before = t.state();
        let nonce = t.grind(per);
        let after = t.state();
        let mut msg = vec![0x05u8];
        msg.extend_from_slice(&before);
        msg.extend_from_slice(&nonce.to_le_bytes());
        let word = u64::from_le_bytes(keccak256(&msg)[..8].try_into().unwrap_or([0xff; 8]));
        println!("grind {i}  nonce {nonce:>12}  leading zeros {:>2}  state {}", word.leading_zeros(), hex(&after));
        rows.push(format!(
            "    {{\"i\": {i}, \"state_before\": \"{}\", \"nonce\": {nonce}, \"word\": \"{:016x}\", \"leading_zeros\": {}, \"state_after\": \"{}\"}}",
            hex(&before),
            word,
            word.leading_zeros(),
            hex(&after)
        ));
    }

    let json = format!(
        "{{\n  \"artifact\": \"grind-kat\",\n  \"label\": \"NONOS-STARK-FRI-EXT\",\n  \
         \"head_absorbed\": \"keccak256(NOX-GRIND-KAT) as a digest\",\n  \"head\": \"{}\",\n  \
         \"grind_bits\": {},\n  \"chunks\": {},\n  \"bits_per_chunk\": {per},\n  \
         \"rule\": \"word = first 8 bytes of keccak256(0x05 || state || nonce le64), little endian; \
         nonce = smallest with leading_zeros(word) >= bits_per_chunk; then state = keccak256(0x05 || state || nonce le64)\",\n  \
         \"grinds\": [\n{}\n  ]\n}}\n",
        hex(&head),
        direct::GRIND_BITS,
        GRIND_CHUNKS,
        rows.join(",\n")
    );
    if let Err(e) = std::fs::write(&out, json) {
        eprintln!("cannot write {out}: {e}");
        std::process::exit(2);
    }
    println!("wrote {out}");
}
