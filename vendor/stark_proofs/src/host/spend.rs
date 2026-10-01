// NONOS Operating System (AGPL-3.0-or-later)

//! A spend of notes that are in a deployed pool, built from the operator's
//! request and the owner's seed file, and refused before any proving if the
//! two do not describe the same pool.
//!
//! Every tool that proves a live spend starts here: the one process prover,
//! and the wallet side of the relayed path. The request is what the pool
//! operator can state: every leaf of the note tree and of the association set
//! in insertion order, the roots the pool published, where the two seed notes
//! sit, the destination and the terms. The seed file is the private half
//! `emit_live_seed` wrote.

use super::request::{die, os_words, pack_u256, quad, try_address, try_unpack_digest, Json};
use crate::crypto::stark::air::{Poseidon, RATE};
use crate::crypto::stark::field::Fp;
use crate::shield::batch::assemble;
use crate::shield::join::{
    intent_parts_anchored, Anchor, AssocAnchor, IntentParts, JoinSplit, Settle, Spend, Witnessed,
};
use crate::shield::key::{derive, Break};
use crate::shield::live_seed::seed_notes;
use crate::shield::member::{PoolTree, TREE_DEPTH};
use crate::shield::note::{note_parts, Note, POOL_LOG_ROUNDS};
use std::io::Write;

pub struct Built {
    pub js: JoinSplit,
    pub note_root: [Fp; RATE],
    pub assoc_root: [Fp; RATE],
}

/// One intent's regions before assembly, so a batch can stack several.
pub struct Parts {
    pub parts: IntentParts,
    pub note_root: [Fp; RATE],
    pub assoc_root: [Fp; RATE],
}

/// One request, one seed, one proof: the single-intent path.
pub fn build_spend(req_text: &str, seed_text: &str, seed_path: &str, outputs_path: &str) -> Built {
    let p = build_parts(req_text, seed_text, seed_path, outputs_path);
    let mut b = assemble(alloc::vec![p.parts]);
    Built {
        js: JoinSplit {
            wired: b.wired,
            witness: b.witness,
            intent: b.intents.remove(0),
        },
        note_root: p.note_root,
        assoc_root: p.assoc_root,
    }
}

/// Several intents under one statement, in the order given: the publics are
/// the intents' words end to end, which is the layout the pool settles a
/// batch by. Each intent is refused on its own terms before any is stacked.
pub fn build_batch(items: &[(String, String, String, String)]) -> Built {
    assert!(!items.is_empty(), "a batch of nothing");
    let built: Vec<Parts> = items
        .iter()
        .map(|(req, seed, seed_path, outputs_path)| build_parts(req, seed, seed_path, outputs_path))
        .collect();
    let note_root = built[0].note_root;
    let assoc_root = built[0].assoc_root;
    let b = assemble(built.into_iter().map(|p| p.parts).collect());
    Built {
        js: JoinSplit {
            wired: b.wired,
            witness: b.witness,
            intent: b.intents.concat(),
        },
        note_root,
        assoc_root,
    }
}

fn tree_of(h: &Poseidon, leaves: &[&str]) -> Result<PoolTree, String> {
    let mut t = PoolTree::with_depth(h.clone(), TREE_DEPTH);
    for l in leaves {
        t.insert(try_unpack_digest(l)?);
    }
    Ok(t)
}

fn opened(t: &PoolTree, index: usize) -> Witnessed {
    Witnessed {
        leaf_index: index,
        siblings: t.path(index).0,
    }
}

/// A private file: created fresh, never overwritten, readable by its owner.
fn write_0600(path: &str, body: &str) {
    let mut open = std::fs::OpenOptions::new();
    open.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(0o600);
    }
    let mut f = open
        .open(path)
        .unwrap_or_else(|e| die(&format!("cannot create {path}: {e}")));
    f.write_all(body.as_bytes())
        .unwrap_or_else(|e| die(&format!("cannot write {path}: {e}")));
}

fn note_json(n: &Note) -> String {
    format!(
        "{{\"value\": {}, \"asset_id\": {}, \"spend_pk\": {:?}, \"blinding\": {:?}}}",
        n.value, n.asset_id, n.spend_pk, n.blinding
    )
}

/// The created notes, the only copy, at 0600 beside the proof: the secrets of
/// the ones this spender owns, and for each one keyed to a receiver, its
/// opening in a file of its own to hand over. A receiver's slot in the
/// outputs file carries a zero secret and `owned: false`, so reading it back
/// as a seed spends only what this spender can.
fn write_private(path: &str, secrets: &[Fp], notes: &[Note; 2], owned: [bool; 2]) {
    let secret = |i: usize| -> [u64; RATE] {
        if owned[i] {
            quad(&secrets[i * RATE..(i + 1) * RATE])
        } else {
            [0; RATE]
        }
    };
    let body = format!(
        "{{\n  \"artifact\": \"settlement-outputs\",\n  \
         \"warning\": \"the only copy of the created notes' secrets\",\n  \
         \"owned\": [{}, {}],\n  \"secrets\": [{:?}, {:?}],\n  \"notes\": [{}, {}]\n}}\n",
        owned[0],
        owned[1],
        secret(0),
        secret(1),
        note_json(&notes[0]),
        note_json(&notes[1])
    );
    write_0600(path, &body);
    println!("outputs   written to {path}, mode 600, the only copy");
    for (i, n) in notes.iter().enumerate() {
        if owned[i] {
            continue;
        }
        let to = format!("{path}.to-{i}.json");
        let body = format!(
            "{{\n  \"artifact\": \"note-opening\",\n  \
             \"warning\": \"hand this to the receiver over a private channel; it opens their note\",\n  \
             \"leaf\": \"{}\",\n  \"note\": {}\n}}\n",
            pack_u256(&note_parts(n).cm),
            note_json(n)
        );
        write_0600(&to, &body);
        println!("output {i} keyed to a receiver; its opening is at {to}, mode 600, for them");
    }
}

/// The notes a spend creates: their secrets (zero where a receiver owns the
/// note), the notes, and which the spender owns. The only copy.
pub struct Created {
    pub secrets: Vec<Fp>,
    pub notes: [Note; 2],
    pub owned: [bool; 2],
}

/// The tools' form: `build_parts_with` over the operating system's randomness,
/// refusals ending the process, the created notes written to `outputs_path`.
pub fn build_parts(req_text: &str, seed_text: &str, seed_path: &str, outputs_path: &str) -> Parts {
    let mut os = |n: usize| -> Result<Vec<Fp>, String> { Ok(os_words(n)) };
    let (parts, created) = build_parts_with(req_text, seed_text, &mut os)
        .unwrap_or_else(|why| die(&format!("{seed_path}: {why}")));
    println!("trees     the pool leaves and association leaves rebuild to the published roots");
    write_private(
        outputs_path,
        &created.secrets,
        &created.notes,
        created.owned,
    );
    parts
}

/// One intent's regions, or a refusal naming what the request got wrong.
///
/// Refused, in order: a leaf list that does not rebuild to the published
/// root, a seed note that is not the leaf it is said to be, an unbalanced
/// spend, two inputs under different assets. The created notes take the
/// inputs' asset and fresh secrets, written to `outputs_path`.
pub fn build_parts_with(
    req_text: &str,
    seed_text: &str,
    words: &mut dyn FnMut(usize) -> Result<Vec<Fp>, String>,
) -> Result<(Parts, Created), String> {
    let req = Json(req_text);
    let pool_leaves = req.try_strings("pool_leaves")?;
    let assoc_leaves = req.try_strings("assoc_leaves")?;
    let pool_at = req.try_u64s("input_pool_index")?;
    let assoc_at = req.try_u64s("input_assoc_index")?;
    let note_root = try_unpack_digest(req.try_string("note_root")?)?;
    let assoc_root = try_unpack_digest(req.try_string("assoc_root")?)?;
    let recipient = try_address(req.try_string("recipient")?)?;
    // The fee's payee, the submitter the user chose. Absent means no fee payee,
    // which only a request with no fee can have.
    let fee_recipient = if req.has("fee_recipient") {
        try_address(req.try_string("fee_recipient")?)?
    } else {
        [0u8; 20]
    };
    let clearing_price = req.try_u64("clearing_price")?;
    /*
     * The earliest settlement time. Required by a `not_before` build and on
     * the grid, so a wallet cannot publish a value that names it; absent and
     * ignored otherwise, where the statement has no word for it.
     */
    let not_before = if cfg!(feature = "not_before") {
        let t = req.try_u64("not_before")?;
        let grid = crate::shield::join::publics::NOT_BEFORE_GRID_S;
        if t == 0 || t % grid != 0 {
            return Err(format!(
                "not_before {t} is not a positive multiple of {grid} seconds"
            ));
        }
        t
    } else {
        0
    };
    let public_amount = req.try_u64("public_amount")?;
    let fee = req.try_u64("fee")?;
    /*
     * The statement names a fee recipient exactly when the fee is nonzero.
     * A fee with no one named would pay the zero address, and a name beside a
     * zero fee is dropped by the circuit, so the request did not say what it
     * meant. Both are refused, as the client refuses them.
     */
    if fee != 0 && fee_recipient == [0u8; 20] {
        return Err("a nonzero fee needs a fee_recipient, the submitter it pays".to_string());
    }
    if fee == 0 && fee_recipient != [0u8; 20] {
        return Err("fee_recipient names a submitter but the fee is zero".to_string());
    }
    let out_values = req.try_u64s("output_values")?;
    if pool_at.len() != 2 || assoc_at.len() != 2 || out_values.len() != 2 {
        return Err(
            "input_pool_index, input_assoc_index and output_values each take exactly two entries"
                .to_string(),
        );
    }

    let (sks, inputs) = seed_notes(seed_text).map_err(|why| format!("seed file: {why}"))?;
    let h = Poseidon::new(POOL_LOG_ROUNDS, [Fp::ZERO; RATE]);

    /*
     * The pool's trees, rebuilt from every leaf the operator listed, and held
     * to the roots the pool published. A list that is missing a deposit or has
     * two swapped rebuilds to a different root, and that is found here rather
     * than as a proof the pool refuses.
     */
    let pool = tree_of(&h, &pool_leaves)?;
    let assoc = tree_of(&h, &assoc_leaves)?;
    if pool.root() != note_root {
        return Err(format!(
            "the {} pool leaves rebuild to {} and the pool published {}; the list is not the pool's",
            pool_leaves.len(),
            pack_u256(&pool.root()),
            pack_u256(&note_root)
        ));
    }
    if assoc.root() != assoc_root {
        return Err(format!(
            "the {} association leaves rebuild to {} and the registry published {}",
            assoc_leaves.len(),
            pack_u256(&assoc.root()),
            pack_u256(&assoc_root)
        ));
    }

    /*
     * The seed notes have to be where the request says they are. A note worth
     * zero is a dummy: the live gate leaves its membership unbound and its
     * nullifier takes the dead lane, so it is in no tree and its index only
     * names the opening its walk runs along.
     */
    for i in 0..2 {
        if inputs[i].value == 0 {
            continue;
        }
        let cm = note_parts(&inputs[i]).cm;
        let at = pool_at[i] as usize;
        if at >= pool_leaves.len() || try_unpack_digest(pool_leaves[at])? != cm {
            return Err(format!("seed note {i} is not the pool's leaf {at}"));
        }
        let at = assoc_at[i] as usize;
        if at >= assoc_leaves.len() || try_unpack_digest(assoc_leaves[at])? != cm {
            return Err(format!(
                "seed note {i} is not the association set's leaf {at}"
            ));
        }
    }

    let inn: u64 = inputs.iter().map(|n| n.value).sum();
    let outv: u64 = out_values.iter().sum();
    if inn != outv + public_amount + fee {
        return Err(format!(
            "does not balance: {inn} in against {outv} out plus {public_amount} public and {fee} fee"
        ));
    }

    /*
     * The created notes carry the asset the inputs carry: the join-split
     * binds all four notes to one asset, so an output under any other id is
     * a statement no proof verifies, found here rather than after proving.
     */
    let asset_id = inputs[0].asset_id;
    if inputs[1].asset_id != asset_id {
        return Err(
            "the two seed notes carry different assets; a transfer moves one asset".to_string(),
        );
    }
    /*
     * Who the created notes belong to. `output_spend_pk` names, per output,
     * a receiver's spend key as the pool word, or "self"; absent, both are
     * this spender's. A note keyed to a receiver is spendable by nobody here,
     * which is what a payment is, and the receiver's later spend of it is
     * the only evidence on chain that it arrived.
     */
    let to: Vec<Option<[Fp; RATE]>> = if req.has("output_spend_pk") {
        let named = req.try_strings("output_spend_pk")?;
        if named.len() != 2 {
            return Err(
                "output_spend_pk takes exactly two entries, a pool word or \"self\"".to_string(),
            );
        }
        named
            .iter()
            .map(|w| {
                if *w == "self" {
                    Ok(None)
                } else {
                    try_unpack_digest(w).map(Some)
                }
            })
            .collect::<Result<Vec<_>, String>>()?
    } else {
        alloc::vec![None, None]
    };
    let owned = [to[0].is_none(), to[1].is_none()];
    let w = words(4 * RATE)?;
    let (osk, oblind) = w.split_at(2 * RATE);
    let outputs: [Note; 2] = core::array::from_fn(|i| {
        let s: [Fp; RATE] = core::array::from_fn(|j| osk[i * RATE + j]);
        Note {
            value: out_values[i],
            asset_id,
            spend_pk: match to[i] {
                Some(pk) => quad(&pk),
                None => quad(&derive(&h, s).spend_pk),
            },
            blinding: quad(&oblind[i * RATE..]),
        }
    });

    let pool_open = [
        opened(&pool, pool_at[0] as usize),
        opened(&pool, pool_at[1] as usize),
    ];
    let assoc_open = [
        opened(&assoc, assoc_at[0] as usize),
        opened(&assoc, assoc_at[1] as usize),
    ];
    let parts = intent_parts_anchored(
        [
            Spend {
                note: &inputs[0],
                sk: sks[0],
            },
            Spend {
                note: &inputs[1],
                sk: sks[1],
            },
        ],
        [&outputs[0], &outputs[1]],
        public_amount,
        fee,
        Break::None,
        Settle {
            clearing_price,
            recipient,
            fee_recipient,
            not_before,
        },
        None,
        TREE_DEPTH,
        Anchor::Published {
            openings: [&pool_open[0], &pool_open[1]],
            root: note_root,
            assoc: Some(AssocAnchor {
                openings: [&assoc_open[0], &assoc_open[1]],
                root: assoc_root,
            }),
        },
    );
    let created = Created {
        secrets: osk.to_vec(),
        notes: outputs,
        owned,
    };
    Ok((
        Parts {
            parts,
            note_root,
            assoc_root,
        },
        created,
    ))
}
