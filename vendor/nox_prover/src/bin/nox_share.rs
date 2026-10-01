// NONOS Operating System (AGPL-3.0-or-later)
//! A proof as a wallet hands it on: format 7, the Merkle paths shared.
//!
//!     nox_share <proof.json> <periodic.top> <out.bin>
//!
//! Reads the proof and its public words from `nox_bench`'s JSON, verifies it
//! against the periodic cache, and writes the format 7 bytes `to_shared`
//! makes, which are what a lander and the pool take. A proof that does not
//! verify is not re-encoded.

fn die(why: &str) -> ! {
    eprintln!("{why}");
    std::process::exit(1)
}

/// The value of `"key": [ ... ]` or `"key": "..."`, as text.
fn field<'a>(json: &'a str, key: &str, open: char, close: char) -> &'a str {
    let at = json
        .find(&format!("\"{key}\": {open}"))
        .unwrap_or_else(|| die(&format!("no {key} in the proof JSON")));
    // past `"key": ` and the opening quote or bracket
    let from = at + key.len() + 5;
    let to = json[from..]
        .find(close)
        .unwrap_or_else(|| die(&format!("{key} is not closed")));
    &json[from..from + to]
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (Some(proof), Some(cache), Some(out)) = (a.first(), a.get(1), a.get(2)) else {
        die("usage: nox_share <proof.json> <periodic.top> <out.bin>")
    };
    let json = std::fs::read_to_string(proof).unwrap_or_else(|e| die(&format!("{proof}: {e}")));
    let cache = std::fs::read(cache).unwrap_or_else(|e| die(&format!("{cache}: {e}")));
    let hex = field(&json, "proof", '"', '"');
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.len() % 2 != 0 {
        die("the proof's hex has an odd length");
    }
    let bytes: Vec<u8> = (0..hex.len() / 2)
        .map(|i| {
            u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
                .unwrap_or_else(|_| die("the proof is not hex"))
        })
        .collect();
    let publics: Vec<u64> = field(&json, "publics", '[', ']')
        .split(',')
        .map(|w| {
            w.trim()
                .parse()
                .unwrap_or_else(|_| die("a public word is not a number"))
        })
        .collect();
    let shared =
        nox_prover::to_shared(&bytes, &publics, &cache).unwrap_or_else(|e| die(&e.to_string()));
    nox_prover::verify_shared(&shared, &publics, &cache).unwrap_or_else(|e| die(&e.to_string()));
    std::fs::write(out, &shared).unwrap_or_else(|e| die(&format!("{out}: {e}")));
    println!(
        "{} bytes in, {} bytes out, format 7, verified",
        bytes.len(),
        shared.len()
    );
}
