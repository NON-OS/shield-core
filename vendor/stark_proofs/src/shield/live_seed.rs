// NONOS Operating System (AGPL-3.0-or-later)
//! The private seed file `emit_live_seed` writes, read back.
//!
//! Two secrets and two notes, every number in document order, which is what
//! the writer fixed and the only thing this relies on. It lives in the
//! library because two tools read it, the one that proves against a pool and
//! the one that prints what a deposit hands the pool, and a reader that
//! existed twice would be one drift away from proving a spend of notes other
//! than the ones deposited.

use super::note::Note;
use crate::crypto::stark::air::RATE;
use crate::crypto::stark::field::Fp;
use alloc::vec::Vec;

fn numbers(s: &str) -> Vec<u64> {
    s.split(|c: char| !c.is_ascii_digit())
        .filter(|t| !t.is_empty())
        .filter_map(|t| t.parse().ok())
        .collect()
}

fn after<'a>(text: &'a str, name: &str) -> Result<&'a str, &'static str> {
    let key = alloc::format!("\"{name}\"");
    let at = text.find(&key).ok_or("seed file: a field is missing")?;
    Ok(&text[at + key.len()..])
}

/// The two secrets and the two notes, or why the file is not a seed file.
pub fn seed_notes(text: &str) -> Result<([[Fp; RATE]; 2], [Note; 2]), &'static str> {
    let secrets_text = after(text, "secrets")?;
    let end = secrets_text.find("]]").ok_or("seed file: secrets unterminated")?;
    let s = numbers(&secrets_text[..end]);
    if s.len() != 2 * RATE {
        return Err("seed file: expected two four-limb secrets");
    }
    let secret = |o: usize| -> [Fp; RATE] { core::array::from_fn(|i| Fp::from_u64(s[o + i])) };

    let notes_text = after(text, "notes")?;
    let end = notes_text.find("}]").ok_or("seed file: notes unterminated")?;
    let n = numbers(&notes_text[..end]);
    // value, asset_id, four of spend_pk, four of blinding, twice.
    if n.len() != 2 * (2 + 2 * RATE) {
        return Err("seed file: expected two notes of value, asset, spend_pk and blinding");
    }
    let note = |o: usize| Note {
        value: n[o],
        asset_id: n[o + 1],
        spend_pk: [n[o + 2], n[o + 3], n[o + 4], n[o + 5]],
        blinding: [n[o + 6], n[o + 7], n[o + 8], n[o + 9]],
    };
    Ok(([secret(0), secret(RATE)], [note(0), note(10)]))
}

/// A digest as the 256 bit word the pool stores it: limb 0 lowest.
pub fn pool_word(limbs: &[Fp; RATE]) -> alloc::string::String {
    let lo = (limbs[0].to_u64() as u128) | ((limbs[1].to_u64() as u128) << 64);
    let hi = (limbs[2].to_u64() as u128) | ((limbs[3].to_u64() as u128) << 64);
    alloc::format!("0x{hi:032x}{lo:032x}")
}
