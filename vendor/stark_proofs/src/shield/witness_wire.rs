// NONOS Operating System (AGPL-3.0-or-later)
//! The witness a wallet hands the prover, on the wire.
//!
//! A client builds a spend in its own language. The intent vector checks the
//! half that needs no prover, which is that the two sides agree on what a
//! transfer is. This is the other half: the private half crossing the
//! boundary, so a proof can be made from a witness a client produced rather
//! than from a fixture the prover built for itself.
//!
//! Flat little-endian `u64` and nothing else. No length prefixes to disagree
//! about, no tags, no nesting: the depth is the second word and every count in
//! the file follows from it, so a reader that has parsed the header knows
//! exactly how many words remain and can say so before allocating. A client in
//! another language writes this with a loop.
//!
//! What it does not carry is anything derivable. No commitments, no nullifiers,
//! no roots the openings already determine: those are the circuit's to compute,
//! and a witness that carried them would be a witness that could disagree with
//! itself. The two roots are the exception and are carried because they are the
//! statement, not a derivation: they are what the pool published.

use super::join::{
    address_of_limbs, join_split_published, AssocAnchor, JoinSplit, Settle, Spend, Witnessed,
};
use super::key::Break;
use super::note::Note;
use crate::crypto::stark::air::RATE;
use crate::crypto::stark::field::Fp;
use alloc::vec::Vec;

/// `NOXWIT02`, so a file that is not this is refused before it is read as this.
/// 02 added the fee recipient's limbs; a 01 file is refused by name rather than
/// read short.
pub const MAGIC: u64 = 0x4E4F_5857_4954_3032;

/// Words a note occupies: value, asset, four of key, four of blinding.
const NOTE_WORDS: usize = 10;

/// The fields before the first opening: magic, depth, two secrets, two input
/// notes, two output notes, the four scalars, and the recipient's and the fee
/// recipient's limbs.
const HEAD_WORDS: usize = 2 + 2 * RATE + 4 * NOTE_WORDS + 4 + 2 * RATE;

/// Everything a prover needs and nothing it can work out for itself.
pub struct SpendWitness {
    pub depth: usize,
    pub secrets: [[Fp; RATE]; 2],
    pub inputs: [Note; 2],
    pub outputs: [Note; 2],
    pub pool: [Witnessed; 2],
    pub note_root: [Fp; RATE],
    pub assoc: [Witnessed; 2],
    pub assoc_root: [Fp; RATE],
    pub public_amount: u64,
    pub fee: u64,
    pub asset_id: u64,
    pub clearing_price: u64,
    pub recipient: [Fp; RATE],
    pub fee_recipient: [Fp; RATE],
}

/// How many words a witness at this depth occupies, exactly.
///
/// A reader checks this before it reads anything, so a truncated file is
/// refused by arithmetic rather than by running out of bytes halfway through an
/// opening and leaving a half-built witness behind.
pub fn words_at(depth: usize) -> usize {
    // Per opening: the leaf index, then one sibling digest per level. Four of
    // them, two per tree, plus a root per tree.
    HEAD_WORDS + 4 * (1 + depth * RATE) + 2 * RATE
}

struct Reader<'a> {
    w: &'a [u64],
    i: usize,
}

impl Reader<'_> {
    fn u64(&mut self) -> u64 {
        let v = self.w[self.i];
        self.i += 1;
        v
    }

    fn fp(&mut self) -> Fp {
        Fp::from_u64(self.u64())
    }

    fn digest(&mut self) -> [Fp; RATE] {
        core::array::from_fn(|_| self.fp())
    }

    fn note(&mut self) -> Note {
        let value = self.u64();
        let asset_id = self.u64();
        let spend_pk = core::array::from_fn(|_| self.u64());
        let blinding = core::array::from_fn(|_| self.u64());
        Note {
            value,
            asset_id,
            spend_pk,
            blinding,
        }
    }

    fn opening(&mut self, depth: usize) -> Witnessed {
        let leaf_index = self.u64() as usize;
        let siblings = (0..depth).map(|_| self.digest()).collect();
        Witnessed {
            leaf_index,
            siblings,
        }
    }
}

/// Read a witness, or say why not.
///
/// Every failure is named. A wallet that wrote a file the prover will not read
/// has to be told which field it got wrong, or the two sides debug each other
/// instead of the file.
pub fn read(words: &[u64]) -> Result<SpendWitness, &'static str> {
    // This format has no word for the earliest settlement time. A `not_before`
    // build refuses it rather than prove with a time nobody chose.
    if cfg!(feature = "not_before") {
        return Err("the witness wire carries no not_before; prove from a request");
    }
    if words.len() < 2 {
        return Err("shorter than a header");
    }
    if words[0] != MAGIC {
        return Err("not a spend witness: the magic word does not match");
    }
    let depth = words[1] as usize;
    if depth == 0 || depth > 64 {
        return Err("depth is not a tree anyone builds");
    }
    if words.len() != words_at(depth) {
        return Err("length does not match the depth the header declares");
    }

    let mut r = Reader { w: words, i: 2 };
    let secrets = [r.digest(), r.digest()];
    let inputs = [r.note(), r.note()];
    let outputs = [r.note(), r.note()];
    let pool = [r.opening(depth), r.opening(depth)];
    let note_root = r.digest();
    let assoc = [r.opening(depth), r.opening(depth)];
    let assoc_root = r.digest();
    let public_amount = r.u64();
    let fee = r.u64();
    let asset_id = r.u64();
    let clearing_price = r.u64();
    let recipient = r.digest();
    if address_of_limbs(&recipient).is_none() {
        return Err("the recipient's limbs are not an address's");
    }
    let fee_recipient = r.digest();
    if address_of_limbs(&fee_recipient).is_none() {
        return Err("the fee recipient's limbs are not an address's");
    }

    Ok(SpendWitness {
        depth,
        secrets,
        inputs,
        outputs,
        pool,
        note_root,
        assoc,
        assoc_root,
        public_amount,
        fee,
        asset_id,
        clearing_price,
        recipient,
        fee_recipient,
    })
}

/// The same witness back out, so a writer in another language has something to
/// compare against word for word.
pub fn write(s: &SpendWitness) -> Vec<u64> {
    let mut w = Vec::with_capacity(words_at(s.depth));
    w.push(MAGIC);
    w.push(s.depth as u64);
    let digest = |w: &mut Vec<u64>, d: &[Fp; RATE]| w.extend(d.iter().map(|v| v.value()));
    for sk in &s.secrets {
        digest(&mut w, sk);
    }
    let note = |w: &mut Vec<u64>, n: &Note| {
        w.push(n.value);
        w.push(n.asset_id);
        w.extend(n.spend_pk);
        w.extend(n.blinding);
    };
    for n in &s.inputs {
        note(&mut w, n);
    }
    for n in &s.outputs {
        note(&mut w, n);
    }
    let opening = |w: &mut Vec<u64>, o: &Witnessed| {
        w.push(o.leaf_index as u64);
        for sib in &o.siblings {
            w.extend(sib.iter().map(|v| v.value()));
        }
    };
    for o in &s.pool {
        opening(&mut w, o);
    }
    digest(&mut w, &s.note_root);
    for o in &s.assoc {
        opening(&mut w, o);
    }
    digest(&mut w, &s.assoc_root);
    w.push(s.public_amount);
    w.push(s.fee);
    w.push(s.asset_id);
    w.push(s.clearing_price);
    digest(&mut w, &s.recipient);
    digest(&mut w, &s.fee_recipient);
    w
}

impl SpendWitness {
    /// The transfer this witness describes, ready to prove.
    ///
    /// Against the roots the witness carries rather than a tree this rebuilds:
    /// the pool published those roots and the openings are the client's claim
    /// about where its notes sit under them. Membership stays what it has always
    /// been, the walked root equalling the published one, and a wrong opening is
    /// honest arithmetic that walks somewhere else and fails there.
    ///
    /// This is the seam between client and prover. Everything above it is a client's, and
    /// everything below is the circuit's.
    pub fn join_split(&self) -> JoinSplit {
        let pool = [&self.pool[0], &self.pool[1]];
        let assoc = AssocAnchor {
            openings: [&self.assoc[0], &self.assoc[1]],
            root: self.assoc_root,
        };
        join_split_published(
            self.depth,
            [
                Spend {
                    note: &self.inputs[0],
                    sk: self.secrets[0],
                },
                Spend {
                    note: &self.inputs[1],
                    sk: self.secrets[1],
                },
            ],
            pool,
            self.note_root,
            assoc,
            [&self.outputs[0], &self.outputs[1]],
            self.public_amount,
            self.fee,
            Break::None,
            Settle {
                not_before: 0,
                clearing_price: self.clearing_price,
                recipient: recipient_bytes(&self.recipient),
                fee_recipient: recipient_bytes(&self.fee_recipient),
            },
            None,
        )
    }
}

/// The recipient back as the twenty bytes a settlement carries, through
/// `address_of_limbs`. The parse refused limbs no address produces, so the
/// fallback is never taken.
fn recipient_bytes(limbs: &[Fp; RATE]) -> [u8; 20] {
    address_of_limbs(limbs).unwrap_or([0; 20])
}
