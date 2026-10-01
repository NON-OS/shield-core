// NONOS Operating System (AGPL-3.0-or-later)

//! What a batch costs the circuit, measured rather than modelled.
//!
//! One payment under its own proof is 96 M gas on chain; the pool takes up
//! to sixty four intents under one proof. The inner batch already exists
//! (`shield::batch::assemble`) and the outer folds whatever inner it is
//! given, so the question is only what shape each side takes as the batch
//! grows: rows, boundaries and DEEP terms, which are the prover's memory
//! and the verifier's bytes. Printed, so a batch size is chosen from a
//! number rather than from sixty four.

use crate::crypto::stark::air::{Air, RATE};
use crate::crypto::stark::field::Fp;
use crate::recursion_assembly::inner::{extra, hasher, hide, pack, prove_raw, GRIND, NQ};
use crate::recursion_assembly::point::Point;
use crate::recursion_assembly::{assemble_over_wired, Tamper};
use crate::shield::batch::assemble;
use crate::shield::join::JoinSplit;
use crate::shield::key::Break;
use crate::shield::test::depth::DEPLOYED;
use crate::shield::test::scenario::balanced_parts_at;
use std::time::Instant;

fn batch_of(n: usize) -> JoinSplit {
    let parts = (0..n).map(|_| balanced_parts_at(DEPLOYED, Break::None)).collect();
    let b = assemble(parts);
    JoinSplit {
        wired: b.wired,
        witness: b.witness,
        intent: b.intents.concat(),
    }
}

/// The inner's shape by batch size: fast, assembly only.
#[test]
#[ignore = "release tier: prints the inner shape per batch size"]
fn print_the_inner_shape_by_batch_size() {
    for n in [1usize, 2, 4, 8, 16, 32, 64] {
        let t = Instant::now();
        let js = batch_of(n);
        let a = &js.wired;
        println!(
            "batch {n:>2}: inner width {} log_t {} rows {} periodic {} transitions {} boundaries {} publics {} built in {:?}",
            a.trace_width(),
            a.log_trace_len(),
            1usize << a.log_trace_len(),
            a.periodic_columns().len(),
            a.num_transition(),
            a.boundary().len(),
            js.intent.len(),
            t.elapsed()
        );
    }
}

/// The outer's shape over a batch inner: the inner is proved for real at the
/// deployment point and the outer assembled at region cap two, which fixes
/// every width and count and leaves only the per-query rows out.
#[test]
#[ignore = "release tier: proves a batch inner per size and assembles the outer"]
fn print_the_outer_shape_by_batch_size() {
    let h = hasher();
    for n in [1usize, 2, 4, 8] {
        let t = Instant::now();
        let mut js = batch_of(n);
        let seed: [Fp; RATE] = core::array::from_fn(|i| Fp::from_u64(0xba7c + i as u64));
        let blind = hide(&h, &mut js, &seed, NQ);
        let inner = pack(&h, prove_raw(&h, js, NQ, GRIND, extra(), &blind), extra(), GRIND);
        let proved = t.elapsed();
        let asm = assemble_over_wired(&h, inner, Tamper::None, 2, Point::emit_wiring());
        let w = &asm.wired;
        println!(
            "batch {n:>2}: inner proved in {:?}; outer at cap 2: width {} log_t {} periodic {} transitions {} boundaries {} deep terms {} publics {}",
            proved,
            w.trace_width(),
            w.log_trace_len(),
            w.periodic_columns().len(),
            w.num_transition(),
            w.boundary().len(),
            2 * w.trace_width() + w.periodic_columns().len() + 1,
            asm.publics.len()
        );
    }
}
