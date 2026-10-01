// NONOS Operating System (AGPL-3.0-or-later)

//! The settlement request as the pool operator states it, and the words a
//! tool reads out of it.

use crate::crypto::stark::air::RATE;
use crate::crypto::stark::field::{Fp, P};
use std::io::Read;

pub fn die(why: &str) -> ! {
    eprintln!("{why}");
    std::process::exit(1)
}

/// The smallest JSON reader that serves one fixed shape. A dependency for
/// this would be the only one in the crate, and the request is flat enough
/// that a reader which refuses anything it does not expect is safer than one
/// that accepts everything.
pub struct Json<'a>(pub &'a str);

impl<'a> Json<'a> {
    /// Whether the request states this field at all; the optional fields
    /// are read only when it does.
    pub fn has(&self, name: &str) -> bool {
        self.0.contains(&format!("\"{name}\""))
    }

    pub fn try_field(&self, name: &str) -> Result<&'a str, String> {
        let key = format!("\"{name}\"");
        let at = self.0.find(&key).ok_or_else(|| format!("request lacks \"{name}\""))?;
        let rest = &self.0[at + key.len()..];
        let colon = rest.find(':').ok_or_else(|| format!("\"{name}\" has no value"))?;
        Ok(rest[colon + 1..].trim_start())
    }

    pub fn try_u64(&self, name: &str) -> Result<u64, String> {
        let v = self.try_field(name)?;
        let end = v.find(|c: char| !c.is_ascii_digit()).unwrap_or(v.len());
        v[..end].parse().map_err(|_| format!("\"{name}\" is not a number"))
    }

    pub fn try_string(&self, name: &str) -> Result<&'a str, String> {
        let v = self.try_field(name)?;
        let v = v.strip_prefix('"').ok_or_else(|| format!("\"{name}\" is not a string"))?;
        let end = v.find('"').ok_or_else(|| format!("\"{name}\" is unterminated"))?;
        Ok(&v[..end])
    }

    pub fn try_strings(&self, name: &str) -> Result<Vec<&'a str>, String> {
        let v = self.try_field(name)?;
        let v = v.strip_prefix('[').ok_or_else(|| format!("\"{name}\" is not a list"))?;
        let end = v.find(']').ok_or_else(|| format!("\"{name}\" is unterminated"))?;
        Ok(v[..end]
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.trim_matches('"'))
            .collect())
    }

    pub fn try_u64s(&self, name: &str) -> Result<Vec<u64>, String> {
        self.try_strings(name)?
            .iter()
            .map(|s| s.parse().map_err(|_| format!("\"{name}\" holds a non-number")))
            .collect()
    }

    // The tools' forms: the same reads, a refusal ends the process.
    pub fn field(&self, name: &str) -> &'a str {
        self.try_field(name).unwrap_or_else(|e| die(&e))
    }

    pub fn u64(&self, name: &str) -> u64 {
        self.try_u64(name).unwrap_or_else(|e| die(&e))
    }

    pub fn string(&self, name: &str) -> &'a str {
        self.try_string(name).unwrap_or_else(|e| die(&e))
    }

    pub fn strings(&self, name: &str) -> Vec<&'a str> {
        self.try_strings(name).unwrap_or_else(|e| die(&e))
    }

    pub fn u64s(&self, name: &str) -> Vec<u64> {
        self.try_u64s(name).unwrap_or_else(|e| die(&e))
    }
}

/// A 256 bit word as the pool stores a digest, `limb0 + limb1 * 2^64 + ...`,
/// back to four field limbs. Refused if any limb is at or above the modulus,
/// because such a word is not a digest this circuit ever produced.
pub fn unpack_digest(hex: &str) -> [Fp; RATE] {
    try_unpack_digest(hex).unwrap_or_else(|e| die(&e))
}

/// `unpack_digest`, refusing with a reason rather than ending the process.
pub fn try_unpack_digest(hex: &str) -> Result<[Fp; RATE], String> {
    let h = hex.trim().trim_start_matches("0x");
    if h.len() > 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{hex} is not a 256 bit hex word"));
    }
    let padded = format!("{h:0>64}");
    let mut limbs = [Fp::ZERO; RATE];
    for (i, limb) in limbs.iter_mut().enumerate() {
        // Limb 0 is the lowest 64 bits, which are the last 16 hex characters.
        let lo = 64 - 16 * (i + 1);
        let v = u64::from_str_radix(&padded[lo..lo + 16], 16).map_err(|_| format!("{hex} is not hex"))?;
        if v >= P {
            return Err(format!("{hex}: limb {i} is {v}, at or above the field modulus"));
        }
        *limb = Fp::from_u64(v);
    }
    Ok(limbs)
}

pub fn pack_u256(limbs: &[Fp; RATE]) -> String {
    let mut lo: u128 = 0;
    let mut hi: u128 = 0;
    for (i, l) in limbs.iter().enumerate() {
        let x = l.to_u64() as u128;
        match i {
            0 => lo |= x,
            1 => lo |= x << 64,
            2 => hi |= x,
            _ => hi |= x << 64,
        }
    }
    format!("0x{hi:032x}{lo:032x}")
}

pub fn address(hex: &str) -> [u8; 20] {
    try_address(hex).unwrap_or_else(|e| die(&e))
}

/// `address`, refusing with a reason rather than ending the process.
pub fn try_address(hex: &str) -> Result<[u8; 20], String> {
    let h = hex.trim().trim_start_matches("0x");
    if h.len() != 40 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("address {hex} is not twenty bytes of hex"));
    }
    let mut a = [0u8; 20];
    for (i, b) in a.iter_mut().enumerate() {
        *b = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).map_err(|_| format!("{hex} is not hex"))?;
    }
    Ok(a)
}

/// Field words from the operating system, rejection sampled rather than
/// reduced so no residue is twice as likely as another.
pub fn os_words(n: usize) -> Vec<Fp> {
    let mut f = std::fs::File::open("/dev/urandom")
        .unwrap_or_else(|e| die(&format!("cannot open /dev/urandom: {e}")));
    let mut out = Vec::with_capacity(n);
    let mut buf = [0u8; 8];
    while out.len() < n {
        f.read_exact(&mut buf)
            .unwrap_or_else(|e| die(&format!("cannot read /dev/urandom: {e}")));
        let v = u64::from_le_bytes(buf);
        if v < P {
            out.push(Fp::from_u64(v));
        }
    }
    out
}

/// Field words from bytes the caller supplies: a browser's
/// `crypto.getRandomValues`, a phone's secure random source, the operating
/// system's. Rejection sampled like `os_words`, and refused rather than
/// stretched when the bytes run out.
pub struct Entropy<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Entropy<'a> {
    pub fn new(bytes: &'a [u8]) -> Entropy<'a> {
        Entropy { bytes, at: 0 }
    }

    pub fn words(&mut self, n: usize) -> Result<Vec<Fp>, String> {
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            let Some(chunk) = self.bytes.get(self.at..self.at + 8) else {
                return Err("not enough entropy: pass at least 512 random bytes".to_string());
            };
            self.at += 8;
            let mut w = [0u8; 8];
            w.copy_from_slice(chunk);
            let v = u64::from_le_bytes(w);
            if v < P {
                out.push(Fp::from_u64(v));
            }
        }
        Ok(out)
    }
}

pub fn quad(w: &[Fp]) -> [u64; RATE] {
    core::array::from_fn(|i| w[i].to_u64())
}

/// A file's text, or why not.
pub fn read_text(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| die(&format!("cannot read {path}: {e}")))
}
