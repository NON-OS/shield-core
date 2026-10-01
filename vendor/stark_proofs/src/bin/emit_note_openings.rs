// NONOS Operating System (AGPL-3.0-or-later)
//! What a deposit hands the pool, for the notes in a private seed file.
//!
//! `absorb` takes a note's opening, not its commitment: the owner digest
//! `compress(spend_pk, blinding)`, the asset, and the value the pool escrows.
//! The pool computes the outer compression itself, so it never sees a key or
//! a blinding and a depositor cannot name a commitment to a note of another
//! value. `emit_live_seed` printed the commitment, which is what a leaf looks
//! like once absorbed and not what absorbing takes.
//!
//!     emit_note_openings <live-seed.json>
//!
//! Nothing private is printed. The owner digest is a Poseidon compression of
//! the key and the blinding and reveals neither; it is exactly the word the
//! pool publishes in its own event once the deposit is mined.

use stark_proofs::shield::live_seed::{pool_word, seed_notes};
use stark_proofs::shield::note::{note_parts, owner_commit};

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: emit_note_openings <live-seed.json>");
        std::process::exit(1)
    };
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        eprintln!("cannot read {path}: {e}");
        std::process::exit(1)
    });
    let (_, notes) = seed_notes(&text).unwrap_or_else(|why| {
        eprintln!("{path}: {why}");
        std::process::exit(1)
    });
    println!("to absorb, per note: ownerCommit, assetId, value; then the leaf it becomes\n");
    for (i, n) in notes.iter().enumerate() {
        println!("  note {i}");
        println!("    ownerCommit  {}", pool_word(&owner_commit(n)));
        println!("    assetId      {}", n.asset_id);
        println!("    value        {}", n.value);
        println!("    cm           {}", pool_word(&note_parts(n).cm));
    }
}
