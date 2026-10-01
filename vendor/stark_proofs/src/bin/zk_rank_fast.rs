// NONOS Operating System (AGPL-3.0-or-later)
//! Condition (R) decided by the fast certificate, for proofs on disk.
//!
//!     zk_rank_fast <proof> <publics.json> [<proof> <publics.json> ...]
//!
//! Prints, per proof, the bound from the positions, the rank certified, and
//! the time. Exits nonzero if any proof is not certified.

use stark_proofs::host::{die, read_text, Json};
use stark_proofs::zk_rank::check_fri_rank;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.is_empty() || !a.len().is_multiple_of(2) {
        die("usage: zk_rank_fast <proof> <publics.json> [<proof> <publics.json> ...]");
    }
    let mut all = true;
    for pair in a.chunks(2) {
        let bytes = std::fs::read(&pair[0]).unwrap_or_else(|e| die(&format!("{}: {e}", pair[0])));
        let publics = Json(&read_text(&pair[1])).u64s("publics");
        let t = std::time::Instant::now();
        match check_fri_rank(&bytes, &publics, 3) {
            Ok(r) => {
                println!(
                    "{}  {}  bound {} certified {} in {} subset(s), {:?}",
                    if r.holds { "HOLDS" } else { "SHORT" },
                    pair[0],
                    r.bound,
                    r.mask_rank,
                    r.attempts,
                    t.elapsed()
                );
                all &= r.holds;
            }
            Err(e) => {
                println!("ERROR  {}: {e}", pair[0]);
                all = false;
            }
        }
    }
    if !all {
        std::process::exit(1);
    }
}
