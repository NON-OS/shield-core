// NONOS Operating System (AGPL-3.0-or-later)
//! Two spendable notes for a live pool, from entropy this repository never
//! publishes.
//!
//! `spec/shield-witness.json` carries the secrets of the spend it describes,
//! because a witness is the private half of one and that file exists so two
//! languages can be diffed against the same spend. The consequence only shows
//! up when a real pool is seeded: anyone holding the repository can derive
//! those notes' nullifier keys, build a valid spend and settle it first. The
//! notes are test value and belong to whoever reads the file. THREAT.md 1d.
//!
//! So a pool that will hold anything gets its seed notes from here instead. The
//! secrets come from the operating system, the private half goes to a path
//! outside this tree, and what reaches stdout is what a depositor needs and
//! nothing else: a commitment and a value per note.
//!
//!     emit_live_seed <private-out> [value0] [value1] [asset]
//!
//! The private file is the only copy. Lose it and the notes are unspendable;
//! publish it and they are anyone's.

use stark_proofs::crypto::stark::air::{Poseidon, RATE};
use stark_proofs::crypto::stark::field::Fp;
use stark_proofs::shield::key::derive;
use stark_proofs::shield::note::{note_parts, owner_commit, Note, POOL_LOG_ROUNDS};
use std::io::{Read, Write};

fn die(why: &str) -> ! {
    eprintln!("{why}");
    std::process::exit(1)
}

/// Field words from the operating system.
///
/// Rejection sampled rather than reduced. A `u64` folded into `[0, P)` by a
/// conditional subtraction is not uniform: every residue below `2^64 - P` is
/// twice as likely as the rest, which is a 32 bit bias on a 64 bit word. It
/// costs nothing to draw again.
fn os_words(n: usize) -> Vec<Fp> {
    let mut f = std::fs::File::open("/dev/urandom")
        .unwrap_or_else(|e| die(&format!("cannot open /dev/urandom: {e}")));
    let mut out = Vec::with_capacity(n);
    let mut buf = [0u8; 8];
    while out.len() < n {
        f.read_exact(&mut buf)
            .unwrap_or_else(|e| die(&format!("cannot read /dev/urandom: {e}")));
        let v = u64::from_le_bytes(buf);
        if v < stark_proofs::crypto::stark::field::P {
            out.push(Fp::from_u64(v));
        }
    }
    out
}

fn quad(w: &[Fp]) -> [u64; RATE] {
    core::array::from_fn(|i| w[i].to_u64())
}

/// The 256 bit word the pool stores a digest as: limb 0 lowest, so
/// `limb0 + limb1 * 2^64 + limb2 * 2^128 + limb3 * 2^192`, the same packing
/// `emit_recursion_pre` publishes the intent words in and the one
/// `prove_settlement_published` reads a leaf list back through.
///
/// The first version of this printed the limbs first to last, which is the
/// same four numbers in the other order and a different 256 bit word. A
/// depositor given that word puts a commitment nobody can spend into the pool
/// and the seed note it was meant to be is never there. One encoding for a
/// digest, and it is the pool's.
fn hex(limbs: &[u64; RATE]) -> String {
    let lo = (limbs[0] as u128) | ((limbs[1] as u128) << 64);
    let hi = (limbs[2] as u128) | ((limbs[3] as u128) << 64);
    format!("{hi:032x}{lo:032x}")
}

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(out) = args.next() else {
        die("usage: emit_live_seed <private-out> [value0] [value1] [asset]")
    };
    let value: [u64; 2] = [
        args.next().map_or(1000, |v| v.parse().expect("value0")),
        args.next().map_or(2000, |v| v.parse().expect("value1")),
    ];
    /*
     * The asset is part of the commitment. A pool pointed at NOX absorbs
     * under NOX's asset id, and a note committed under another id is a leaf
     * that pool's own recomputation never lands on, so the depositor's id and
     * this one have to be the same number and it is taken as an argument
     * rather than assumed.
     */
    let asset_id: u64 = args.next().map_or(0, |v| v.parse().expect("asset"));

    /*
     * The private half must not land in the tree. A secret under `spec/` or
     * anywhere else this repository publishes is a secret with a countdown on
     * it, and the whole point of this tool is that these two are not that.
     */
    let manifest = env!("CARGO_MANIFEST_DIR");
    let repo = std::path::Path::new(manifest)
        .parent()
        .unwrap_or_else(|| die("the manifest directory has no parent"));
    let abs = std::path::Path::new(&out)
        .canonicalize()
        .unwrap_or_else(|_| std::path::PathBuf::from(&out));
    if abs.starts_with(repo) {
        die(&format!(
            "{out} is inside {}, and the private half of a live note does not \
             go in the repository. Give a path outside it.",
            repo.display()
        ));
    }

    let h = Poseidon::new(POOL_LOG_ROUNDS, [Fp::ZERO; RATE]);
    let w = os_words(4 * RATE);
    let (sk, blind) = w.split_at(2 * RATE);

    let notes: [Note; 2] = core::array::from_fn(|i| {
        let s: [Fp; RATE] = core::array::from_fn(|j| sk[i * RATE + j]);
        Note {
            value: value[i],
            asset_id,
            spend_pk: quad(&derive(&h, s).spend_pk),
            blinding: quad(&blind[i * RATE..]),
        }
    });
    let cm: [[Fp; RATE]; 2] = core::array::from_fn(|i| note_parts(&notes[i]).cm);

    let secrets: Vec<String> = (0..2)
        .map(|i| {
            let s: [u64; RATE] = core::array::from_fn(|j| sk[i * RATE + j].to_u64());
            format!("{s:?}")
        })
        .collect();
    let private = format!(
        "{{\n  \"artifact\": \"live-seed\",\n  \
         \"warning\": \"the only copy of these secrets; the notes are \
         unspendable without it and anyone's with it\",\n  \
         \"secrets\": [{}],\n  \
         \"notes\": [{}]\n}}\n",
        secrets.join(","),
        (0..2)
            .map(|i| format!(
                "{{\"value\": {}, \"asset_id\": {}, \"spend_pk\": {:?}, \"blinding\": {:?}}}",
                notes[i].value, notes[i].asset_id, notes[i].spend_pk, notes[i].blinding
            ))
            .collect::<Vec<_>>()
            .join(",")
    );

    /*
     * Created at 0600 rather than created and then restricted. Chmod after
     * create leaves the secrets world readable for as long as the write takes,
     * which is short and is not zero.
     */
    let mut open = std::fs::OpenOptions::new();
    open.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(0o600);
    }
    let mut f = open
        .open(&out)
        .unwrap_or_else(|e| die(&format!("cannot create {out}: {e}")));
    f.write_all(private.as_bytes())
        .unwrap_or_else(|e| die(&format!("cannot write {out}: {e}")));

    println!("private half written to {out}, mode 600, the only copy");
    println!("\nto deposit, per note: commitment then value\n");
    for i in 0..2 {
        let limbs: [u64; RATE] = core::array::from_fn(|j| cm[i][j].to_u64());
        println!(
            "  note {i}  cm 0x{}  value {}  asset {}",
            hex(&limbs),
            notes[i].value,
            notes[i].asset_id
        );
        println!("           limbs {limbs:?}");
        /*
         * `absorb` takes the owner digest, not the commitment: the pool
         * computes the commitment itself from the value it escrowed.
         */
        let owner = owner_commit(&notes[i]);
        let owner: [u64; RATE] = core::array::from_fn(|j| owner[j].to_u64());
        println!("           absorb owner 0x{}", hex(&owner));
    }
}
