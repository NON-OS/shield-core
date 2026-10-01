// NONOS Operating System (AGPL-3.0-or-later)

use crate::crypto::stark::air::Poseidon;
use crate::crypto::stark::fri_poseidon_ext::FriProofExtP;
use crate::crypto::stark::field::{Fp, Fp2};
use crate::crypto::stark::fri::root_of_unity;
use crate::crypto::stark::poly::eval;

extern crate alloc;
use alloc::vec::Vec;
#[allow(unused_imports)]
use super::{openings::*, compose::*, wired_a::*, wired_b::*, codeword::*, wired_c::*};

pub(super) const RATE: usize = 4;

pub(super) fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// A low-degree extension codeword: a base polynomial of degree `< d` evaluated on
/// the coset, lifted into `Fp2`.
pub(super) fn low_degree_ext(log_n: u32, d: usize, shift: Fp, seed: u64) -> Vec<Fp2> {
    let n = 1usize << log_n;
    let omega = root_of_unity(log_n);
    let mut s = seed | 1;
    let coeffs: Vec<Fp> = (0..d).map(|_| Fp::from_u64(xorshift(&mut s))).collect();
    let mut x = shift;
    let mut cw = Vec::with_capacity(n);
    for _ in 0..n {
        cw.push(Fp2::from_base(eval(&coeffs, x)));
        x = x * omega;
    }
    cw
}

pub(super) fn hasher() -> Poseidon {
    Poseidon::new(2, [Fp::ZERO; RATE])
}

pub(super) fn squaring_trace(log_t: u32, seed: Fp) -> Vec<Fp> {
    let t = 1usize << log_t;
    let mut trace = Vec::with_capacity(t);
    let mut cur = seed;
    for _ in 0..t {
        trace.push(cur);
        cur = cur * cur;
    }
    trace
}

#[test]
fn a_poseidon_committed_stark_proves_and_verifies() {
    use crate::crypto::stark::air::{
        stark_prove_poseidon_ext, stark_verify_poseidon_ext, Squaring,
    };
    let seed = Fp::from_u64(3);
    let air = Squaring { log_t: 4, seed };
    let trace = squaring_trace(4, seed);
    let h = hasher();
    let proof = stark_prove_poseidon_ext(&air, &trace, 32, 8, 0, &h);
    assert!(
        stark_verify_poseidon_ext(&air, &proof, 32, 8, 0, &h),
        "an honest Poseidon-committed STARK was rejected"
    );
}

#[test]
fn a_tampered_poseidon_committed_stark_is_rejected() {
    use crate::crypto::stark::air::{
        stark_prove_poseidon_ext, stark_verify_poseidon_ext, Squaring,
    };
    let seed = Fp::from_u64(3);
    let air = Squaring { log_t: 4, seed };
    let mut trace = squaring_trace(4, seed);
    trace[2] = trace[2] + Fp::from_u64(1); // break the squaring relation
    let h = hasher();
    let proof = stark_prove_poseidon_ext(&air, &trace, 32, 8, 0, &h);
    assert!(
        !stark_verify_poseidon_ext(&air, &proof, 32, 8, 0, &h),
        "a tampered Poseidon-committed STARK verified"
    );
}

#[test]
fn a_poseidon_committed_join_split_core_proves_and_verifies() {
    // The real inner proof recursion folds over: the wired conservation + range
    // join-split core, committed with Poseidon at deployment soundness (rate 1/16).
    use crate::crypto::stark::air::{
        stark_prove_poseidon_ext, stark_verify_poseidon_ext, Accumulator, AirExt, RangeCheck,
        WiredExt,
    };
    use alloc::boxed::Box;

    let regions: Vec<Box<dyn AirExt>> = alloc::vec![
        Box::new(Accumulator { log_t: 3 }) as Box<dyn AirExt>,
        Box::new(RangeCheck { log_t: 4 }),
    ];
    let mut sigma: Vec<usize> = (0..32).collect();
    sigma.swap(1, 8); // conservation acc[1] (=input 7) wired to range acc[0]
    let wired = WiredExt::new(
        regions,
        alloc::vec![0],
        sigma,
        Fp::from_u64(5),
        Fp::from_u64(7),
    );

    let neg = |x: u64| -> Fp { Fp::ZERO - Fp::from_u64(x) };
    let addends = [
        Fp::from_u64(7),
        Fp::from_u64(3),
        neg(8),
        neg(1),
        neg(1),
        Fp::ZERO,
        Fp::ZERO,
        Fp::ZERO,
    ];
    let mut cons = Vec::with_capacity(addends.len() * 2);
    let mut acc = Fp::ZERO;
    for &a in &addends {
        cons.push(acc);
        cons.push(a);
        acc = acc + a;
    }
    let mut rng = Vec::with_capacity(32);
    let mut v = 7u64;
    for i in 0..16usize {
        let bit = if i < 15 { v & 1 } else { 0 };
        rng.push(Fp::from_u64(v));
        rng.push(Fp::from_u64(bit));
        if i < 15 {
            v >>= 1;
        }
    }
    let witness = wired.trace(&[cons, rng]);
    let h = hasher();
    let proof = stark_prove_poseidon_ext(&wired, &witness, 32, 16, 3, &h);
    assert!(
        stark_verify_poseidon_ext(&wired, &proof, 32, 16, 3, &h),
        "the Poseidon-committed join-split core was rejected"
    );
}

// Build the real Poseidon-committed join-split core proof recursion folds over,
// returning the AIR alongside so its verification witness can be extracted.
/// The FRI domain of a proof whose final layer is the final polynomial:
/// the folds, the blowup and the coefficient count together.
pub(super) fn fri_log_n(air: &impl crate::crypto::stark::air::AirExt, fri: &FriProofExtP, extra: u32) -> u32 {
    let (_, log_blowup) = crate::crypto::stark::air::domain_params_blown(air, extra);
    fri.roots.len() as u32 + log_blowup + fri.final_layer.len().trailing_zeros()
}

/// Query `q`'s final value: the final polynomial at its last point.
pub(super) fn fri_final_value(fri: &FriProofExtP, log_n: u32, q: usize) -> Fp2 {
    use crate::crypto::stark::fri::{final_point, horner};
    let n_folds = fri.roots.len();
    let n = 1usize << log_n;
    horner(&fri.final_layer, final_point(Fp::from_u64(7), root_of_unity(log_n), q % (n >> n_folds), n_folds))
}

pub(super) fn poseidon_join_split_proof(
    h: &Poseidon,
    nq: usize,
    grind: u32,
    extra: u32,
) -> (
    crate::crypto::stark::air::WiredExt,
    crate::crypto::stark::air::StarkProofExtP,
) {
    use crate::crypto::stark::air::{
        stark_prove_poseidon_ext, Accumulator, AirExt, RangeCheck, WiredExt,
    };
    use alloc::boxed::Box;
    let regions: Vec<Box<dyn AirExt>> = alloc::vec![
        Box::new(Accumulator { log_t: 3 }) as Box<dyn AirExt>,
        Box::new(RangeCheck { log_t: 4 }),
    ];
    let mut sigma: Vec<usize> = (0..32).collect();
    sigma.swap(1, 8);
    let wired = WiredExt::new(
        regions,
        alloc::vec![0],
        sigma,
        Fp::from_u64(5),
        Fp::from_u64(7),
    );
    let neg = |x: u64| -> Fp { Fp::ZERO - Fp::from_u64(x) };
    let addends = [
        Fp::from_u64(7),
        Fp::from_u64(3),
        neg(8),
        neg(1),
        neg(1),
        Fp::ZERO,
        Fp::ZERO,
        Fp::ZERO,
    ];
    let mut cons = Vec::new();
    let mut acc = Fp::ZERO;
    for &a in &addends {
        cons.push(acc);
        cons.push(a);
        acc = acc + a;
    }
    let mut rng = Vec::new();
    let mut v = 7u64;
    for i in 0..16usize {
        let bit = if i < 15 { v & 1 } else { 0 };
        rng.push(Fp::from_u64(v));
        rng.push(Fp::from_u64(bit));
        if i < 15 {
            v >>= 1;
        }
    }
    let witness = wired.trace(&[cons, rng]);
    let proof = stark_prove_poseidon_ext(&wired, &witness, nq, grind, extra, h);
    (wired, proof)
}

// The first real recursion fragment over the actual inner proof: take the real
// Poseidon join-split proof's FRI, replay its transcript to recover the Fp2 fold
// challenges, then prove IN-CIRCUIT (a STARK) that its query-0 fold chain is
// consistent. This is verification of the real proof's low-degree test, arithmetized.
#[test]
fn the_real_poseidon_fri_fold_chain_verifies_in_circuit() {
    use crate::crypto::stark::air::{stark_prove_ext, stark_verify_ext, TraceFoldExt};
    use crate::crypto::stark::field::Fp2;
    use crate::crypto::stark::poseidon_transcript::PoseidonTranscript;

    let h = hasher();
    let (nq, grind, extra) = (32usize, 16u32, 3u32);
    let (_air, proof) = poseidon_join_split_proof(&h, nq, grind, extra);
    let fri = &proof.fri;
    let n_folds = fri.roots.len();
    let log_n = fri_log_n(&_air, fri, extra);
    let n = 1usize << log_n;

    // Replay the FRI transcript to recover the fold challenges and the first index.
    let mut ts = PoseidonTranscript::new(h.clone());
    // The seed the STARK transcript hands FRI, absorbed before layer zero.
    let seed = crate::crypto::stark::air::replay::replay(&_air, &proof, None, None, extra, &h, &[]).seed;
    ts.absorb(seed[0]);
    ts.absorb(seed[1]);
    let mut betas: Vec<Fp2> = Vec::with_capacity(n_folds);
    for root in &fri.roots {
        ts.absorb_digest(root);
        betas.push(ts.challenge_fp2());
    }
    for value in &fri.final_layer {
        ts.absorb(value.c0);
        ts.absorb(value.c1);
    }
    assert!(
        ts.verify_pow(fri.pow_nonce, grind),
        "P's FRI proof-of-work did not check"
    );
    let q0 = ts.challenge_index(n);

    // Extract query 0's real openings and the public domain data per layer.
    let final_value = fri_final_value(fri, log_n, q0);
    let base_omega = root_of_unity(log_n);
    let shift = Fp::from_u64(7);
    let layers = &fri.queries[0].layers;
    let (mut a, mut b) = (Vec::new(), Vec::new());
    let (mut x_inv, mut dir) = (Vec::new(), Vec::new());
    for (m, op) in layers.iter().enumerate() {
        a.push(op.a);
        b.push(op.b);
        let half = n >> (m + 1);
        let i = q0 % half;
        let x = (shift * base_omega.pow(i as u64)).pow(1u64 << m);
        x_inv.push(x.inv());
        let half_next = n >> (m + 2);
        dir.push(i >= half_next);
    }
    a.push(final_value);
    b.push(final_value);

    let log_layers = (n_folds + 1).next_power_of_two().trailing_zeros();
    let fold = TraceFoldExt::new(log_layers, n_folds, x_inv, dir, final_value);
    let ftrace = fold.trace(&betas, &a, &b);
    let fproof = stark_prove_ext(&fold, &ftrace, 32, 8);
    assert!(
        stark_verify_ext(&fold, &fproof, 32, 8),
        "the real Poseidon join-split proof's FRI fold chain was rejected in-circuit"
    );
}
