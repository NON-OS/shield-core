//! What a scan costs per output.
//!
//! Discovery asks nobody anything, so the wallet fetches every output and
//! tries it. The bandwidth is arithmetic from the wire format; this is the
//! other half, the work per output, which decides whether a full scan is a
//! design or a wish.
//!
//! Each output costs one key agreement and one hash to reach its view tag, and
//! an authenticated decryption only on the roughly one in 256 whose tag
//! matches. The sample here is built so none of them is ours, which is the
//! common case and the one that has to be cheap.
//!
//! ```sh
//! cargo run --release --example scan_cost
//! ```

use nox_shield_core::custody::{generate_phrase, phrase_to_seed};
use nox_shield_core::discovery::{scan, PoolOutput};
use nox_shield_core::keys::Account;
use nox_shield_core::notes::{
    commitment, commitment_bytes, fresh_blinding, seal_note, NotePlaintext, CIPHER_LEN,
};
use nox_shield_core::prover::pool_hasher;
use std::time::Instant;

const OUTPUTS: usize = 20_000;

fn main() {
    let phrase = match generate_phrase() {
        Ok(p) => p,
        Err(e) => return eprintln!("scan_cost: {e}"),
    };
    let seed = match phrase_to_seed(&phrase) {
        Ok(s) => s,
        Err(e) => return eprintln!("scan_cost: {e}"),
    };
    let mine = match Account::from_seed(&seed) {
        Ok(a) => a,
        Err(e) => return eprintln!("scan_cost: {e}"),
    };

    let outputs = match sample(OUTPUTS) {
        Ok(o) => o,
        Err(e) => return eprintln!("scan_cost: {e}"),
    };
    let wire = OUTPUTS.saturating_mul(8 + 32 + CIPHER_LEN);

    let started = Instant::now();
    let (found, stats) = scan(&mine, &outputs);
    let elapsed = started.elapsed();

    let per = elapsed.as_secs_f64() / OUTPUTS as f64;
    println!("outputs          {OUTPUTS}");
    println!("wire bytes       {wire}");
    println!("elapsed          {elapsed:?}");
    println!("per output       {:.3} us", per * 1e6);
    println!("outputs a second {:.0}", 1.0 / per);
    println!("agreements       {}", stats.agreements);
    println!("tag hits         {}", stats.tag_hits);
    println!("found            {}", found.len());
}

/// Outputs addressed to somebody else, which is what a scan mostly sees.
fn sample(count: usize) -> Result<Vec<PoolOutput>, nox_shield_core::error::WalletError> {
    let h = pool_hasher();
    let mut out = Vec::with_capacity(count);
    for index in 0..count {
        let phrase = generate_phrase()?;
        let stranger = Account::from_seed(&phrase_to_seed(&phrase)?)?;
        let address = stranger.address();
        let plain = NotePlaintext {
            value: 1000,
            asset_id: 0,
            blinding: fresh_blinding()?,
            spend_pk: address.spend_pk,
        };
        let cm = commitment(&h, &plain.note());
        let cipher = seal_note(&plain, &address, &commitment_bytes(&cm))?;
        out.push(PoolOutput {
            leaf_index: index as u64,
            cm: [cm[0].value(), cm[1].value(), cm[2].value(), cm[3].value()],
            cipher: cipher.encode(),
        });
    }
    Ok(out)
}
