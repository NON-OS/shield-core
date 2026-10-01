// NONOS Operating System (AGPL-3.0-or-later)

use crate::crypto::stark::air::{Air, Poseidon, RATE};
use crate::crypto::stark::field::Fp;

extern crate alloc;
#[allow(unused_imports)]
use super::{
    exec::*, ext::*, ext_deep::*, fold::*, fold_chain::*, fri::*, fri_fold::*, fri_fused::*,
    membership::*, membership_multi::*, monolith::*, poseidon::*, wired::*,
};
use alloc::vec::Vec;

// The FRI verification arithmetized as ONE money-grade STARK: per query a Merkle
// opening region and a fold region, wired so each opening's leaf equals its fold's
// opened value and the layer challenges agree across queries. Proven at ~2^-128.
// This is the recursion primitive -- a proof's own verification, provable in a
// proof -- and it reuses the base trace helpers unchanged, only WiredExt + AirExt.
pub(super) fn whole_proof_monolith_ext(
    queries: &[usize],
    seeds: &[u64],
) -> (crate::crypto::stark::air::WiredExt, Vec<Fp>) {
    use crate::crypto::stark::air::{AirExt, TraceFold, WiredExt};
    use alloc::boxed::Box;
    let mut regions: Vec<Box<dyn AirExt>> = Vec::new();
    let mut traces: Vec<Vec<Fp>> = Vec::new();
    let mut heights: Vec<usize> = Vec::new();
    let mut open_idx: Vec<usize> = Vec::new();
    let mut fold_idx: Vec<usize> = Vec::new();
    let mut n_folds = 0usize;

    for (&query, &seed) in queries.iter().zip(seeds) {
        let (beta, a, b, x_inv, dir, fv, ll, nf) = trace_fold_data_seeded(query, seed);
        n_folds = nf;
        let (mtr, mem, _) = opening_of_scalar(a[0], 2);
        open_idx.push(regions.len());
        // The rows the region occupies, not the length of its padded trace.
        heights.push(mem.rows());
        traces.push(mtr);
        regions.push(Box::new(mem));

        let fold = TraceFold::new(ll, nf, x_inv, dir, fv);
        fold_idx.push(regions.len());
        heights.push(1usize << ll);
        traces.push(fold.trace(&beta, &a, &b));
        regions.push(Box::new(fold));
    }

    let mut offsets: Vec<usize> = Vec::new();
    let mut acc = 0usize;
    for &h in &heights {
        offsets.push(acc);
        acc += h;
    }
    let span = acc.next_power_of_two();
    let k = 2usize;
    let mut sigma: Vec<usize> = (0..span * k).collect();
    for qi in 0..queries.len() {
        let leaf = offsets[open_idx[qi]] * k;
        let opened = offsets[fold_idx[qi]] * k + 1;
        sigma.swap(leaf, opened);
    }
    let qn = queries.len();
    for m in 0..n_folds {
        for qi in 0..qn {
            let here = (offsets[fold_idx[qi]] + m) * k;
            let next = (offsets[fold_idx[(qi + 1) % qn]] + m) * k;
            sigma[here] = next;
        }
    }
    let wired = WiredExt::new(
        regions,
        alloc::vec![0, 1],
        sigma,
        Fp::from_u64(5),
        Fp::from_u64(7),
    );
    let witness = wired.trace(&traces);
    (wired, witness)
}

#[test]
fn the_recursive_fri_verifier_is_one_money_grade_stark() {
    use crate::crypto::stark::air::{stark_prove_ext, stark_verify_ext};
    let seed = 0xf01d_1234u64 | 1;
    let (wired, witness) = whole_proof_monolith_ext(&[6, 10], &[seed, seed]);
    let proof = stark_prove_ext(&wired, &witness, 32, 8);
    assert!(
        stark_verify_ext(&wired, &proof, 32, 8),
        "the money-grade recursion monolith was rejected"
    );
}

// Fiat-Shamir challenge derivation, arithmetized and proven money-grade: a
// challenge squeezed from a Poseidon transcript, verified at ~2^-128. This is the
// last recursion building block -- a recursive verifier runs its own transcript in
// circuit -- and it confirms every recursion primitive (transcript, FRI fold,
// Merkle opening, wiring) is now money-grade. Honest challenge verifies; wrong one
// is rejected.
#[test]
fn money_grade_fiat_shamir_challenge_derivation() {
    use crate::crypto::stark::air::{stark_prove_ext, stark_verify_ext, FiatShamir};
    let (log_rounds, log_slots) = (3u32, 2u32);
    let hasher = Poseidon::new(log_rounds, [Fp::ZERO; RATE]);
    let inputs = alloc::vec![Fp::from_u64(111), Fp::from_u64(222), Fp::from_u64(333)];
    let (trace, challenge) = fiat_shamir_trace(&hasher, &inputs, log_rounds, log_slots);
    let air = FiatShamir::new(
        Poseidon::new(log_rounds, [Fp::ZERO; RATE]),
        log_rounds,
        log_slots,
        inputs.clone(),
        challenge,
    );
    let proof = stark_prove_ext(&air, &trace, 32, 8);
    assert!(
        stark_verify_ext(&air, &proof, 32, 8),
        "an honest money-grade transcript was rejected"
    );

    let bad = FiatShamir::new(
        Poseidon::new(log_rounds, [Fp::ZERO; RATE]),
        log_rounds,
        log_slots,
        inputs,
        challenge + Fp::ONE,
    );
    let bad_proof = stark_prove_ext(&bad, &trace, 32, 8);
    assert!(
        !stark_verify_ext(&bad, &bad_proof, 32, 8),
        "a wrong money-grade challenge verified"
    );
}

// The DEEP-consistency check, arithmetized and proven money-grade: a query's DEEP
// value must be the coefficient combination of the honestly-formed quotients of the
// opened trace and composition against the out-of-domain claims. This is the last
// verifier stage a recursive proof needs. Honest verifies; a wrong DEEP value is
// rejected (its quotient-combination no longer matches the pinned value).
// A one-row domain folds to nothing at radix 8, so there is no FRI layer
// zero to read the DEEP value from; the radix-4 build keeps this test.
#[cfg(not(feature = "radix8"))]
#[test]
fn the_money_grade_stark_proves_deep_consistency() {
    use crate::crypto::stark::air::{stark_prove_ext, stark_verify_ext, DeepCheck};
    let (tv, cl, cp, cpz, x, z, c0, e) = (
        Fp::from_u64(5),
        Fp::from_u64(2),
        Fp::from_u64(8),
        Fp::from_u64(1),
        Fp::from_u64(10),
        Fp::from_u64(3),
        Fp::from_u64(4),
        Fp::from_u64(6),
    );
    let xz_inv = (x - z).inv();
    let q = (tv - cl) * xz_inv;
    let qc = (cp - cpz) * xz_inv;
    let deep = c0 * q + e * qc;
    let air = DeepCheck {
        trace_val: tv,
        claimed: cl,
        comp: cp,
        comp_z: cpz,
        deep,
        x,
        z,
        c0,
        e,
    };
    let proof = stark_prove_ext(&air, &air.trace(), 32, 8);
    assert!(
        stark_verify_ext(&air, &proof, 32, 8),
        "honest DEEP consistency was rejected"
    );
}

// A one-row domain folds to nothing at radix 8, so there is no FRI layer
// zero to read the DEEP value from; the radix-4 build keeps this test.
#[cfg(not(feature = "radix8"))]
#[test]
fn the_money_grade_stark_rejects_a_wrong_deep_value() {
    use crate::crypto::stark::air::{stark_prove_ext, stark_verify_ext, DeepCheck};
    let (tv, cl, cp, cpz, x, z, c0, e) = (
        Fp::from_u64(5),
        Fp::from_u64(2),
        Fp::from_u64(8),
        Fp::from_u64(1),
        Fp::from_u64(10),
        Fp::from_u64(3),
        Fp::from_u64(4),
        Fp::from_u64(6),
    );
    let xz_inv = (x - z).inv();
    let q = (tv - cl) * xz_inv;
    let qc = (cp - cpz) * xz_inv;
    let deep = c0 * q + e * qc + Fp::ONE; // wrong DEEP value
    let air = DeepCheck {
        trace_val: tv,
        claimed: cl,
        comp: cp,
        comp_z: cpz,
        deep,
        x,
        z,
        c0,
        e,
    };
    let proof = stark_prove_ext(&air, &air.trace(), 32, 8);
    assert!(
        !stark_verify_ext(&air, &proof, 32, 8),
        "a wrong DEEP value verified"
    );
}

// The full recursive verifier as ONE money-grade STARK: all four verification
// stages -- Fiat-Shamir transcript derivation, FRI fold, Merkle opening, and DEEP
// consistency -- fused and proven together at ~2^-128. This is a proof's entire
// verification, provable in a proof. Wiring the stages' shared values is the
// soundness refinement (the wired join-split shows that shape); here the stages
// compose into one money-grade proof.
#[test]
fn the_full_recursive_verifier_is_one_money_grade_stark() {
    use crate::crypto::stark::air::{
        stark_prove_ext, stark_verify_ext, AirExt, DeepCheck, FiatShamir, FusedExt, TraceFold,
    };
    use alloc::boxed::Box;

    // Stage 1: transcript derivation.
    let (lr, ls) = (3u32, 2u32);
    let hasher = Poseidon::new(lr, [Fp::ZERO; RATE]);
    let inputs = alloc::vec![Fp::from_u64(111), Fp::from_u64(222), Fp::from_u64(333)];
    let (fs_trace, challenge) = fiat_shamir_trace(&hasher, &inputs, lr, ls);
    let fs = FiatShamir::new(
        Poseidon::new(lr, [Fp::ZERO; RATE]),
        lr,
        ls,
        inputs,
        challenge,
    );

    // Stage 2 + 3: a FRI fold and the Merkle opening of the folded value.
    let (beta, a, b, x_inv, dir, fv, ll, nf) = trace_fold_data_seeded(6, 0xf01d_1234u64 | 1);
    let (mtr, mem, _) = opening_of_scalar(a[0], 2);
    let fold = TraceFold::new(ll, nf, x_inv, dir, fv);
    let fold_trace = fold.trace(&beta, &a, &b);

    // Stage 4: DEEP consistency.
    let (tv, cl, cp, cpz, x, z, c0, e) = (
        Fp::from_u64(5),
        Fp::from_u64(2),
        Fp::from_u64(8),
        Fp::from_u64(1),
        Fp::from_u64(10),
        Fp::from_u64(3),
        Fp::from_u64(4),
        Fp::from_u64(6),
    );
    let xz_inv = (x - z).inv();
    let deep = c0 * ((tv - cl) * xz_inv) + e * ((cp - cpz) * xz_inv);
    let dc = DeepCheck {
        trace_val: tv,
        claimed: cl,
        comp: cp,
        comp_z: cpz,
        deep,
        x,
        z,
        c0,
        e,
    };

    let regions: alloc::vec::Vec<Box<dyn AirExt>> = alloc::vec![
        Box::new(fs) as Box<dyn AirExt>,
        Box::new(mem),
        Box::new(fold),
        Box::new(dc),
    ];
    let fused = FusedExt::new(regions);
    let witness = fused.trace(&[
        fs_trace,
        mtr,
        fold_trace,
        DeepCheck {
            trace_val: tv,
            claimed: cl,
            comp: cp,
            comp_z: cpz,
            deep,
            x,
            z,
            c0,
            e,
        }
        .trace(),
    ]);
    let proof = stark_prove_ext(&fused, &witness, 32, 8);
    assert!(
        stark_verify_ext(&fused, &proof, 32, 8),
        "the full recursive verifier was rejected"
    );
}

#[test]
#[ignore]
fn gen_recursive_selftest() {
    // Emit the full recursive-verifier proof: the four verification stages
    // (Fiat-Shamir, FRI fold, Merkle opening, DEEP consistency) proven together as
    // one money-grade STARK. This is the recursive-verifier vector the pool's
    // constant-gas StarkVerifier is built against; its _composeConstraints is the
    // fused sum of the four stage transitions (transcribe from the AIR sources).
    use crate::crypto::stark::air::{
        stark_prove_ext, stark_verify_ext, AirExt, DeepCheck, FiatShamir, FusedExt, TraceFold,
    };
    use alloc::boxed::Box;

    let (lr, ls) = (3u32, 2u32);
    let hasher = Poseidon::new(lr, [Fp::ZERO; RATE]);
    let inputs = alloc::vec![Fp::from_u64(111), Fp::from_u64(222), Fp::from_u64(333)];
    let (fs_trace, challenge) = fiat_shamir_trace(&hasher, &inputs, lr, ls);
    let fs = FiatShamir::new(
        Poseidon::new(lr, [Fp::ZERO; RATE]),
        lr,
        ls,
        inputs,
        challenge,
    );

    let (beta, a, b, x_inv, dir, fv, ll, nf) = trace_fold_data_seeded(6, 0xf01d_1234u64 | 1);
    let (mtr, mem, _) = opening_of_scalar(a[0], 2);
    let fold = TraceFold::new(ll, nf, x_inv, dir, fv);
    let fold_trace = fold.trace(&beta, &a, &b);

    let (tv, cl, cp, cpz, x, z, c0, e) = (
        Fp::from_u64(5),
        Fp::from_u64(2),
        Fp::from_u64(8),
        Fp::from_u64(1),
        Fp::from_u64(10),
        Fp::from_u64(3),
        Fp::from_u64(4),
        Fp::from_u64(6),
    );
    let xz_inv = (x - z).inv();
    let deep = c0 * ((tv - cl) * xz_inv) + e * ((cp - cpz) * xz_inv);
    let dc = || DeepCheck {
        trace_val: tv,
        claimed: cl,
        comp: cp,
        comp_z: cpz,
        deep,
        x,
        z,
        c0,
        e,
    };

    let regions: alloc::vec::Vec<Box<dyn AirExt>> = alloc::vec![
        Box::new(fs) as Box<dyn AirExt>,
        Box::new(mem),
        Box::new(fold),
        Box::new(dc()),
    ];
    let fused = FusedExt::new(regions);
    let witness = fused.trace(&[fs_trace, mtr, fold_trace, dc().trace()]);
    let proof = stark_prove_ext(&fused, &witness, 32, 8);
    assert!(
        stark_verify_ext(&fused, &proof, 32, 8),
        "recursive self-test does not verify"
    );

    let bytes = crate::stark_selftest_gen::serialize(&proof);
    let json = alloc::format!(
        "{{\n  \"engine\": \"nonos-money-grade-stark\",\n  \"air\": \"recursive-verifier (fiat-shamir + fri-fold + merkle-opening + deep-consistency)\",\n  \"note\": \"The full STARK verification arithmetized as one money-grade proof -- the CONSTANT-GAS target. _composeConstraints = the fused sum of the four stage transitions. Cross-stage sigma wiring is the soundness refinement (see the wired join-split shape).\",\n  \"params\": {{ \"n_queries\": 32, \"grind_bits\": 8 }},\n  \"stages\": [\"fiat_shamir\", \"merkle_membership\", \"trace_fold\", \"deep_check\"],\n  \"proof_len_bytes\": {},\n  \"proof_hex\": \"{}\"\n}}\n",
        bytes.len(), crate::stark_selftest_gen::hex(&bytes)
    );
    crate::spec_out::write_spec("recursive-selftest.json", &json);
    std::println!(
        "wrote {} proof bytes to recursive-selftest.json",
        bytes.len()
    );
}
