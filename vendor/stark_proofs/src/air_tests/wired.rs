// NONOS Operating System (AGPL-3.0-or-later)

use crate::crypto::stark::air::{
    Poseidon, RATE,
};
use crate::crypto::stark::field::Fp;

extern crate alloc;
use alloc::vec::Vec;
#[allow(unused_imports)]
use super::{exec::*, poseidon::*, membership::*, fri::*, fold::*, monolith::*, ext::*, recursive::*, fri_fold::*, fri_fused::*, ext_deep::*, fold_chain::*, membership_multi::*};

// The cross-stage wiring that makes the recursive verifier SOUND: the value a
// Merkle opening reveals is bound by a copy constraint to the value the DEEP check
// consumes, so the two stages cannot be about different values. Proven money-grade;
// a mismatched value is rejected. This is the wiring the full recursive verifier
// uses to bind transcript->FRI->DEEP->Merkle; here it binds Merkle->DEEP.
pub(super) fn wired_recursive_check(deep_val: Fp) -> (crate::crypto::stark::air::WiredExt, Vec<Fp>) {
    use crate::crypto::stark::air::{Air, AirExt, DeepCheck, WiredExt};
    use alloc::boxed::Box;
    let scalar = Fp::from_u64(777);
    let (mtr, mem, _) = opening_of_scalar(scalar, 2);
    // Where the next region starts, which is the rows this one occupies rather
    // than the length of its padded trace.
    let mem_height = mem.rows();

    let (cl, cp, cpz, x, z, c0, e) = (
        Fp::from_u64(2),
        Fp::from_u64(8),
        Fp::from_u64(1),
        Fp::from_u64(10),
        Fp::from_u64(3),
        Fp::from_u64(4),
        Fp::from_u64(6),
    );
    let xz_inv = (x - z).inv();
    // Honest DEEP value is the combination for THIS trace_val (deep_val).
    let deep = c0 * ((deep_val - cl) * xz_inv) + e * ((cp - cpz) * xz_inv);
    let dc =
        DeepCheck { trace_val: deep_val, claimed: cl, comp: cp, comp_z: cpz, deep, x, z, c0, e };
    let dc_trace = dc.trace();

    let regions: Vec<Box<dyn AirExt>> = alloc::vec![Box::new(mem) as Box<dyn AirExt>, Box::new(dc)];
    let span = (mem_height + 2).next_power_of_two();
    let mut sigma: Vec<usize> = (0..span).collect();
    // Merkle leaf (row 0, col 0) <-> DEEP trace_val (row mem_height, col 0).
    sigma.swap(0, mem_height);
    let wired = WiredExt::new(regions, alloc::vec![0], sigma, Fp::from_u64(5), Fp::from_u64(7));
    let witness = wired.trace(&[mtr, dc_trace]);
    (wired, witness)
}

#[test]
fn the_wired_recursive_verifier_binds_stages() {
    use crate::crypto::stark::air::{stark_prove_ext, stark_verify_ext};
    // The DEEP value uses the SAME value the Merkle opening revealed (777).
    let (wired, witness) = wired_recursive_check(Fp::from_u64(777));
    let proof = stark_prove_ext(&wired, &witness, 32, 8);
    assert!(
        stark_verify_ext(&wired, &proof, 32, 8),
        "an honestly-bound recursive verifier was rejected"
    );
}

#[test]
fn the_wired_recursive_verifier_rejects_a_stage_mismatch() {
    use crate::crypto::stark::air::{stark_prove_ext, stark_verify_ext};
    // The DEEP check uses a DIFFERENT value (888) than the Merkle opening (777):
    // the wire between stages breaks.
    let (wired, witness) = wired_recursive_check(Fp::from_u64(888));
    let proof = stark_prove_ext(&wired, &witness, 32, 8);
    assert!(
        !stark_verify_ext(&wired, &proof, 32, 8),
        "a stage-mismatched recursive verifier verified"
    );
}

#[test]
#[ignore]
fn gen_recursive_public_selftest() {
    // The recursive-verifier vector WITH its public statement: the proof plus every
    // boundary triple and every periodic column, so the verifier can reconstruct
    // periodic_z and compose_ext and actually run. Poseidon round constants are
    // regenerable from the schedule, but included here so the vector is fully
    // self-contained and testable.
    use crate::crypto::stark::air::{
        stark_prove_ext, stark_verify_ext, Air, AirExt, DeepCheck, FiatShamir, FusedExt, TraceFold,
    };
    use alloc::boxed::Box;
    use alloc::string::String;

    let (lr, ls) = (3u32, 2u32);
    let hasher = Poseidon::new(lr, [Fp::ZERO; RATE]);
    let inputs = alloc::vec![Fp::from_u64(111), Fp::from_u64(222), Fp::from_u64(333)];
    let (fs_trace, challenge) = fiat_shamir_trace(&hasher, &inputs, lr, ls);
    let fs = FiatShamir::new(Poseidon::new(lr, [Fp::ZERO; RATE]), lr, ls, inputs, challenge);
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
    let dc = || DeepCheck { trace_val: tv, claimed: cl, comp: cp, comp_z: cpz, deep, x, z, c0, e };

    let regions: alloc::vec::Vec<Box<dyn AirExt>> =
        alloc::vec![Box::new(fs) as Box<dyn AirExt>, Box::new(mem), Box::new(fold), Box::new(dc())];
    let fused = FusedExt::new(regions);
    let witness = fused.trace(&[fs_trace, mtr, fold_trace, dc().trace()]);
    let proof = stark_prove_ext(&fused, &witness, 32, 8);
    assert!(stark_verify_ext(&fused, &proof, 32, 8), "recursive public self-test does not verify");

    // Public statement: boundaries + periodic columns.
    let mut bnd = String::from("[");
    for (i, (c, r, v)) in fused.boundary().iter().enumerate() {
        if i > 0 {
            bnd.push(',');
        }
        bnd.push_str(&alloc::format!("[{},{},\"{}\"]", c, r, v.value()));
    }
    bnd.push(']');
    let mut per = String::from("[");
    for (i, col) in fused.periodic_columns().iter().enumerate() {
        if i > 0 {
            per.push(',');
        }
        per.push('[');
        for (j, v) in col.iter().enumerate() {
            if j > 0 {
                per.push(',');
            }
            per.push_str(&alloc::format!("\"{}\"", v.value()));
        }
        per.push(']');
    }
    per.push(']');

    let bytes = crate::stark_selftest_gen::serialize(&proof);
    let json = alloc::format!(
        "{{\n  \"engine\": \"nonos-money-grade-stark\",\n  \"air\": \"recursive-verifier (fiat-shamir + fri-fold + merkle-opening + deep-consistency)\",\n  \"note\": \"Full recursive verification with its PUBLIC STATEMENT. boundaries = (col,row,value) pins; periodic_columns = every periodic column expanded (selectors, per-stage instance data, Poseidon RCs). The verifier reconstructs periodic_z via eval_lagrange_ext and runs compose_ext. This is the FusedExt composition; cross-stage sigma wiring is the soundness refinement.\",\n  \"log_trace_len\": {}, \"trace_width\": {}, \"n_queries\": 32, \"grind_bits\": 8,\n  \"stages\": [\"fiat_shamir\", \"merkle_membership\", \"trace_fold\", \"deep_check\"],\n  \"boundaries\": {},\n  \"periodic_columns\": {},\n  \"proof_len_bytes\": {},\n  \"proof_hex\": \"{}\"\n}}\n",
        fused.log_trace_len(), fused.trace_width(), bnd, per, bytes.len(), crate::stark_selftest_gen::hex(&bytes)
    );
    crate::spec_out::write_spec("recursive-selftest.json", &json);
    std::println!(
        "wrote proof {} bytes + {} boundaries + {} periodic cols",
        bytes.len(),
        fused.boundary().len(),
        fused.periodic_columns().len()
    );
}

// How to fault the wired recursive verifier, so each wire is shown load-bearing.
pub(super) enum RecursiveFault {
    None,
    // The DEEP check is about a value the opening never committed.
    RebindValue(Fp),
    // The fold runs on a challenge the transcript never squeezed.
    UnboundChallenge(Fp),
}

// The fully wired 4-stage recursive verifier: the same four stages the fused vector
// composes (Fiat-Shamir, Merkle opening, FRI fold, DEEP consistency), now bound end
// to end by one grand-product column carrying two cross-stage cycles:
//   value flow: Merkle-opened value == fold input == DEEP trace value.
//   transcript: Fiat-Shamir challenge == the fold's first-layer beta.
// So the four stages are provably about one value and driven by one challenge; a
// verifier can neither fold or DEEP-check a value the opening never revealed, nor
// fold on a challenge the transcript never squeezed. A faulted wire breaks the
// product without touching any region's own constraint. This is the custody-flip
// shape the pool's constant-gas verifier points at.
pub(super) fn wired_recursive_verifier(
    fault: RecursiveFault,
) -> (crate::crypto::stark::air::WiredExt, Vec<Fp>) {
    use crate::crypto::stark::air::{AirExt, DeepCheck, FiatShamir, TraceFold, WiredExt};
    use alloc::boxed::Box;

    // Stage 1: transcript derivation.
    let (lr, ls) = (3u32, 2u32);
    let hasher = Poseidon::new(lr, [Fp::ZERO; RATE]);
    let inputs = alloc::vec![Fp::from_u64(111), Fp::from_u64(222), Fp::from_u64(333)];
    let (fs_trace, challenge) = fiat_shamir_trace(&hasher, &inputs, lr, ls);
    let fs = FiatShamir::new(Poseidon::new(lr, [Fp::ZERO; RATE]), lr, ls, inputs, challenge);

    // Stage 2 + 3: the Merkle opening of a[0], and the fold that consumes a[0]. The
    // fold's first beta is the transcript challenge, unless faulted off-transcript.
    let fold_beta0 = match fault {
        RecursiveFault::UnboundChallenge(b) => b,
        _ => challenge,
    };
    let (beta, a, b, x_inv, dir, fv, ll, nf) =
        trace_fold_data_seeded_first(6, 0xf01d_1234u64 | 1, Some(fold_beta0));
    let (mtr, mem, _) = opening_of_scalar(a[0], 2);
    let fold = TraceFold::new(ll, nf, x_inv, dir, fv);
    let fold_trace = fold.trace(&beta, &a, &b);

    // Stage 4: DEEP consistency, honestly formed for whatever value it is about.
    let deep_val = match fault {
        RecursiveFault::RebindValue(v) => v,
        _ => a[0],
    };
    let (cl, cp, cpz, x, z, c0, e) = (
        Fp::from_u64(2),
        Fp::from_u64(8),
        Fp::from_u64(1),
        Fp::from_u64(10),
        Fp::from_u64(3),
        Fp::from_u64(4),
        Fp::from_u64(6),
    );
    let xz_inv = (x - z).inv();
    let deep = c0 * ((deep_val - cl) * xz_inv) + e * ((cp - cpz) * xz_inv);
    let dc =
        DeepCheck { trace_val: deep_val, claimed: cl, comp: cp, comp_z: cpz, deep, x, z, c0, e };
    let dc_trace = dc.trace();

    let regions: Vec<Box<dyn AirExt>> =
        alloc::vec![Box::new(fs) as Box<dyn AirExt>, Box::new(mem), Box::new(fold), Box::new(dc),];

    // Region row offsets exactly as Stack::of lays them: each region takes the
    // rows it occupies. The FS challenge sits at row (2^ls - 1) * 2^lr, column 0.
    let mut offs = Vec::with_capacity(regions.len());
    let mut row = 0usize;
    for r in &regions {
        offs.push(row);
        row += r.rows();
    }
    let span = row.next_power_of_two();
    let (o_mem, o_fold, o_dc) = (offs[1], offs[2], offs[3]);
    let fs_challenge_row = ((1usize << ls) - 1) * (1usize << lr);

    // wired columns 0 and 1, so k = 2 and a cell's id is row*2 + wired_index.
    let k = 2usize;
    let mut sigma: Vec<usize> = (0..span * k).collect();
    // Value-flow 3-cycle: Merkle leaf (col 0) -> fold input (col 1) -> DEEP (col 0).
    let (id_mem, id_fold_a, id_dc) = (o_mem * k, o_fold * k + 1, o_dc * k);
    sigma[id_mem] = id_fold_a;
    sigma[id_fold_a] = id_dc;
    sigma[id_dc] = id_mem;
    // Transcript 2-cycle: FS challenge (col 0) <-> fold first beta (col 0).
    sigma.swap(fs_challenge_row * k, o_fold * k);

    let wired = WiredExt::new(regions, alloc::vec![0, 1], sigma, Fp::from_u64(5), Fp::from_u64(7));
    let witness = wired.trace(&[fs_trace, mtr, fold_trace, dc_trace]);
    (wired, witness)
}

// The honestly wired recursive verifier: opened == folded == DEEP-checked value, and
// the fold runs on the transcript challenge. Both cross-stage cycles telescope, and
// the proof verifies at ~2^-128.
#[test]
fn the_full_wired_recursive_verifier_binds_the_value_flow() {
    use crate::crypto::stark::air::{stark_prove_ext, stark_verify_ext};
    let (wired, witness) = wired_recursive_verifier(RecursiveFault::None);
    let proof = stark_prove_ext(&wired, &witness, 32, 8);
    assert!(
        stark_verify_ext(&wired, &proof, 32, 8),
        "the honestly wired recursive verifier was rejected"
    );
}

// The DEEP check is about a value the Merkle stage never opened. Its own constraint
// still holds, but the value-flow wire breaks, so the grand product no longer
// returns to one and the proof is rejected.
#[test]
fn the_full_wired_recursive_verifier_rejects_a_rebound_value() {
    use crate::crypto::stark::air::{stark_prove_ext, stark_verify_ext};
    let (wired, witness) =
        wired_recursive_verifier(RecursiveFault::RebindValue(Fp::from_u64(0xD1FF)));
    let proof = stark_prove_ext(&wired, &witness, 32, 8);
    assert!(!stark_verify_ext(&wired, &proof, 32, 8), "a rebound recursive verifier verified");
}

// The fold runs on a challenge the transcript never squeezed. The fold is internally
// consistent for that challenge, but the transcript wire breaks, so the proof is
// rejected. This is what forces the recursive verifier to be honest about Fiat-Shamir.
#[test]
fn the_full_wired_recursive_verifier_rejects_an_off_transcript_fold() {
    use crate::crypto::stark::air::{stark_prove_ext, stark_verify_ext};
    let (wired, witness) =
        wired_recursive_verifier(RecursiveFault::UnboundChallenge(Fp::from_u64(0xBAD0)));
    let proof = stark_prove_ext(&wired, &witness, 32, 8);
    assert!(!stark_verify_ext(&wired, &proof, 32, 8), "an off-transcript fold verified");
}

#[test]
#[ignore]
fn gen_wired_recursive_public_selftest() {
    // The WIRED recursive-verifier vector with its public statement: the same four
    // stages as the fused vector, plus the one grand-product column that binds the
    // opened value to the folded and DEEP-checked value AND the transcript challenge
    // to the fold's beta. The verifier gains exactly one product term in its compose
    // and one boundary pinning that column to one; everything else (transcript, FRI,
    // Merkle, Fp2, periodic eval) is unchanged. This is the custody-flip vector.
    use crate::crypto::stark::air::{stark_prove_ext_blown, stark_verify_ext_blown, Air};
    use alloc::string::String;

    // Deployment soundness. The FRI runs at rate 1/2 by default (1 conjectured bit
    // per query), so the 32-query test instances are only ~40-bit. For a fund gate
    // the vector is generated at rate 1/16 (EXTRA_BLOWUP_BITS = 3, 4 conjectured
    // bits per query): 32 queries give 128 bits and 16 grind bits add margin.
    const EXTRA_BLOWUP_BITS: u32 = 3;
    const N_QUERIES: usize = 32;
    const GRIND_BITS: u32 = 16;

    let (wired, witness) = wired_recursive_verifier(RecursiveFault::None);
    let proof = stark_prove_ext_blown(&wired, &witness, N_QUERIES, GRIND_BITS, EXTRA_BLOWUP_BITS);
    assert!(
        stark_verify_ext_blown(&wired, &proof, N_QUERIES, GRIND_BITS, EXTRA_BLOWUP_BITS),
        "wired recursive deployment self-test does not verify"
    );

    // The wiring must still reject at the deployment parameters, not just in the
    // fast tests: a value the opening never committed breaks the grand product.
    let (bad, bad_w) = wired_recursive_verifier(RecursiveFault::RebindValue(Fp::from_u64(0xD1FF)));
    let bad_proof = stark_prove_ext_blown(&bad, &bad_w, N_QUERIES, GRIND_BITS, EXTRA_BLOWUP_BITS);
    assert!(
        !stark_verify_ext_blown(&bad, &bad_proof, N_QUERIES, GRIND_BITS, EXTRA_BLOWUP_BITS),
        "a rebound value verified at deployment parameters"
    );

    let mut bnd = String::from("[");
    for (i, (c, r, v)) in wired.boundary().iter().enumerate() {
        if i > 0 {
            bnd.push(',');
        }
        bnd.push_str(&alloc::format!("[{},{},\"{}\"]", c, r, v.value()));
    }
    bnd.push(']');
    let mut per = String::from("[");
    for (i, col) in wired.periodic_columns().iter().enumerate() {
        if i > 0 {
            per.push(',');
        }
        per.push('[');
        for (j, v) in col.iter().enumerate() {
            if j > 0 {
                per.push(',');
            }
            per.push_str(&alloc::format!("\"{}\"", v.value()));
        }
        per.push(']');
    }
    per.push(']');

    let bytes = crate::stark_selftest_gen::serialize(&proof);
    let json = alloc::format!(
        "{{\n  \"engine\": \"nonos-money-grade-stark\",\n  \"air\": \"wired-recursive-verifier (fiat-shamir + merkle-opening + fri-fold + deep-consistency, fully bound)\",\n  \"note\": \"The WIRED recursive verification with its PUBLIC STATEMENT, at DEPLOYMENT soundness. Adds one grand-product column to the fused composition carrying two cross-stage cycles: a value-flow cycle binds the Merkle-opened value to the fold input and the DEEP trace value, and a transcript cycle binds the Fiat-Shamir challenge to the fold's first beta. So the four stages are provably about one value and driven by one challenge. The FRI runs at rate 1/16 (extra_blowup_bits=3, fri_log_blowup=4), so 32 queries give 128 conjectured bits and 16 grind bits add margin. _composeConstraints = the fused sum of the four stage transitions PLUS the one grand-product term; boundaries include the product column pinned to one at row 0 and row span.\",\n  \"wiring\": {{ \"wired_cols\": [0, 1], \"beta\": 5, \"gamma\": 7 }},\n  \"soundness\": {{ \"extra_blowup_bits\": 3, \"fri_log_blowup\": 4, \"conjectured_bits\": 144, \"regime\": \"proximity-gap-conjectured\" }},\n  \"log_trace_len\": {}, \"trace_width\": {}, \"n_queries\": 32, \"grind_bits\": 16,\n  \"stages\": [\"fiat_shamir\", \"merkle_membership\", \"trace_fold\", \"deep_check\", \"grand_product\"],\n  \"boundaries\": {},\n  \"periodic_columns\": {},\n  \"proof_len_bytes\": {},\n  \"proof_hex\": \"{}\"\n}}\n",
        wired.log_trace_len(), wired.trace_width(), bnd, per, bytes.len(), crate::stark_selftest_gen::hex(&bytes)
    );
    crate::spec_out::write_spec("wired-recursive-selftest.json", &json);
    std::println!(
        "wrote wired proof {} bytes + {} boundaries + {} periodic cols",
        bytes.len(),
        wired.boundary().len(),
        wired.periodic_columns().len()
    );
}

// A hostile capsule can put any 32-bit count in the trailer before the data
// that would back it. The deserializer must refuse such a trailer without first
// reserving gigabytes for a vector it will never fill. This builds a trailer
// that reaches the first length field and sets it to its maximum; the parser
// must return None promptly, which it cannot do if it pre-allocates the count.
#[test]
fn a_hostile_length_prefix_is_refused_without_overallocating() {
    use crate::crypto::stark::air::deserialize_proof_ext;
    let mut trailer = Vec::new();
    trailer.extend_from_slice(&[0u8; 32]); // trace_root
    trailer.extend_from_slice(&[0u8; 32]); // comp_root
    trailer.extend_from_slice(&0u32.to_le_bytes()); // ood frame: zero elements
    trailer.extend_from_slice(&u32::MAX.to_le_bytes()); // FRI roots: 2^32 - 1
    assert!(
        deserialize_proof_ext(&trailer).is_none(),
        "a trailer with a hostile length prefix must be refused"
    );
}
