// NONOS Operating System (AGPL-3.0-or-later)
//! Every transcript operation of a real launch proof's verification, as a
//! known-answer vector a port checks itself against one step at a time.
//!
//!     emit_transcript_kat <proof> <publics.json> <out.json>
//!
//! Build with `--features kat`. The proof is verified by the production
//! verifier with the transcript recording, so the vector is what the verifier
//! does and not a second account of it. Each event is one `mix`: its tag, the
//! bytes absorbed, where those bytes sit in the proof when they come from it,
//! and the state after. A draw (tags 0x03, 0x04, 0x06, 0x07) is the state's
//! first eight bytes read little endian; a query index is that word masked to
//! the domain, a base challenge that word reduced mod p. Bytes absorbed that
//! are not in the proof (the public words, a seed handed between transcripts)
//! carry `"at": null`.

use stark_proofs::host::die;

#[cfg(feature = "kat")]
fn main() {
    use stark_proofs::crypto::stark::air::{periodic_root, stark_verify_ext_rounds_why};
    use stark_proofs::crypto::stark::field::Fp;
    use stark_proofs::crypto::stark::transcript::kat;
    use stark_proofs::host::{read_text, Json};
    use stark_proofs::proof_wire::{deserialize_rounds, ParamSet};
    use stark_proofs::shield::join::join_split_shape;
    use stark_proofs::shield::member::TREE_DEPTH;
    use stark_proofs::shield_params::direct;

    let a: Vec<String> = std::env::args().skip(1).collect();
    let (Some(proof_path), Some(pub_path), Some(out)) = (a.first(), a.get(1), a.get(2)) else {
        die("usage: emit_transcript_kat <proof> <publics.json> <out.json>")
    };
    let (q, grind, extra) = (direct::N_QUERIES, direct::GRIND_BITS, direct::EXTRA_BLOWUP_BITS);
    let words: Vec<Fp> = Json(&read_text(pub_path)).u64s("publics").into_iter().map(Fp::from_u64).collect();
    let air = join_split_shape(TREE_DEPTH, &words);
    let params = ParamSet::of(&air, q, grind, extra);
    let bytes = std::fs::read(proof_path).unwrap_or_else(|e| die(&format!("cannot read {proof_path}: {e}")));
    let rounds = deserialize_rounds(&bytes, &params).unwrap_or_else(|| die("not a proof at the launch point"));
    let root = periodic_root(&air, extra);
    let _ = kat::take();
    if let Err(why) = stark_verify_ext_rounds_why(air, &rounds, q, grind, extra, &root, &words) {
        die(&format!("the proof does not verify, no vector: {why}"));
    }
    let events = kat::take();

    let hex = |b: &[u8]| -> String { b.iter().map(|x| format!("{x:02x}")).collect() };
    let find = |needle: &[u8], from: usize| -> Option<usize> {
        if needle.is_empty() || needle.len() > bytes.len() {
            return None;
        }
        (from..=bytes.len() - needle.len()).find(|&i| &bytes[i..i + needle.len()] == needle)
    };
    /*
     * The public words are absorbed as one run of field elements, and a small
     * word like zero would also be found somewhere in the proof by a search.
     * The run is recognised by its content instead and labelled as publics.
     */
    let pub_bytes: Vec<[u8; 8]> = words.iter().map(|w| w.to_u64().to_le_bytes()).collect();
    let mut from_publics = vec![false; events.len()];
    for i in 0..events.len().saturating_sub(pub_bytes.len().saturating_sub(1)) {
        let run = &events[i..i + pub_bytes.len()];
        if run.iter().zip(&pub_bytes).all(|(e, b)| e.tag == 0x02 && e.data == b[..]) {
            from_publics[i..i + pub_bytes.len()].iter_mut().for_each(|f| *f = true);
            break;
        }
    }
    let mut cursor = 0usize;
    let mut rows = Vec::with_capacity(events.len());
    let (mut located, mut absorbed) = (0usize, 0usize);
    for (i, e) in events.iter().enumerate() {
        let op = match e.tag {
            0x00 => "new",
            0x01 => "absorb_digest",
            0x02 => "absorb_fp",
            0x03 => "challenge_fp",
            0x04 => "challenge_index",
            0x05 => "absorb_nonce",
            0x06 => "challenge_fp2_c0",
            0x07 => "challenge_fp2_c1",
            0x08 => "challenge_seed",
            _ => "other",
        };
        let source = if from_publics[i] {
            "publics"
        } else if matches!(e.tag, 0x01 | 0x02 | 0x05) {
            "proof"
        } else {
            "drawn"
        };
        let at = if source == "proof" {
            absorbed += 1;
            // Wire order and absorb order mostly agree, so look forward from
            // the last hit first, then anywhere.
            let hit = find(&e.data, cursor).or_else(|| find(&e.data, 0));
            if let Some(h) = hit {
                located += 1;
                cursor = h + e.data.len();
            }
            hit
        } else {
            None
        };
        let word = u64::from_le_bytes(e.state[..8].try_into().unwrap_or([0; 8]));
        let draw = if matches!(e.tag, 0x03 | 0x04 | 0x06 | 0x07) { format!(", \"word\": \"{word:016x}\"") } else { String::new() };
        rows.push(format!(
            "    {{\"i\": {i}, \"op\": \"{op}\", \"tag\": {}, \"source\": \"{source}\", \"data\": \"{}\", \"at\": {}, \"state\": \"{}\"{draw}}}",
            e.tag,
            hex(&e.data),
            at.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
            hex(&e.state)
        ));
    }
    let json = format!(
        "{{\n  \"artifact\": \"transcript-kat\",\n  \"proof\": \"{proof_path}\",\n  \"publics\": \"{pub_path}\",\n  \
         \"proof_bytes\": {},\n  \"point\": [{q}, {grind}, {extra}],\n  \"events\": {},\n  \
         \"rule\": \"state = keccak256(tag || state || data); new: state = keccak256(label); a draw's word is state[0..8] little endian\",\n  \
         \"events_list\": [\n{}\n  ]\n}}\n",
        bytes.len(),
        events.len(),
        rows.join(",\n")
    );
    std::fs::write(out, json).unwrap_or_else(|e| die(&format!("cannot write {out}: {e}")));
    let n_pub = from_publics.iter().filter(|f| **f).count();
    println!("wrote {out}: {} events, {n_pub} public words, {located} of {absorbed} proof items located", events.len());
}

#[cfg(not(feature = "kat"))]
fn main() {
    die("build with --features kat: the transcript records only in that build");
}
