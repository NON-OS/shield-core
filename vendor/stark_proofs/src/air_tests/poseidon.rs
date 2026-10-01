// NONOS Operating System (AGPL-3.0-or-later)

use crate::crypto::stark::air::{
    stark_prove, stark_verify, Fibonacci, Poseidon, PowerChain,
    Squaring, RATE, WIDTH,
};
use crate::crypto::stark::field::Fp;

extern crate alloc;
use alloc::vec::Vec;
#[allow(unused_imports)]
use super::{exec::*, membership::*, fri::*, fold::*, monolith::*, ext::*, recursive::*, wired::*, fri_fold::*, fri_fused::*, ext_deep::*, fold_chain::*, membership_multi::*};

/// Number of Poseidon rounds used by the tests, as log2. The round count is a
/// security parameter; this is a representative value that exercises the engine.
pub(super) const POSEIDON_LOG_T: u32 = 5;

/// Build a Poseidon trace from a full initial state, returning the trace and the
/// digest (the rate lanes at the final row).
pub(super) fn poseidon_trace(air: &Poseidon, initial: [Fp; WIDTH], log_t: u32) -> (Vec<Fp>, [Fp; RATE]) {
    let t = 1usize << log_t;
    let mut state = initial;
    let mut trace = Vec::with_capacity(WIDTH * t);
    for r in 0..t {
        trace.extend_from_slice(&state);
        if r < t - 1 {
            state = air.round(&state, r);
        }
    }
    let mut digest = [Fp::ZERO; RATE];
    digest.copy_from_slice(&trace[(t - 1) * WIDTH..(t - 1) * WIDTH + RATE]);
    (trace, digest)
}

/// A full initial state that absorbs a rate-sized input with the capacity zeroed.
pub(super) fn absorb(input: [Fp; RATE]) -> [Fp; WIDTH] {
    let mut state = [Fp::ZERO; WIDTH];
    state[..RATE].copy_from_slice(&input);
    state
}

pub(super) fn sample_input() -> [Fp; RATE] {
    [Fp::from_u64(11), Fp::from_u64(22), Fp::from_u64(33), Fp::from_u64(44)]
}

#[test]
fn poseidon_hashing_diffuses_and_is_deterministic() {
    // A real hash: one changed input lane changes every digest lane (full
    // diffusion through the MDS layer over the rounds), and it is deterministic.
    let air = Poseidon::new(POSEIDON_LOG_T, [Fp::ZERO; RATE]);
    let a = air.hash(&sample_input());
    let mut other = sample_input();
    other[3] = other[3] + Fp::ONE;
    let b = air.hash(&other);
    for i in 0..RATE {
        assert_ne!(a[i], b[i], "digest lane {i} did not diffuse");
    }
    assert_eq!(a, air.hash(&sample_input()), "hash is not deterministic");
}

#[test]
fn an_honest_poseidon_preimage_verifies() {
    // Prove knowledge of an input that Poseidon-hashes to a public digest,
    // without the input appearing in the public statement.
    let params = Poseidon::new(POSEIDON_LOG_T, [Fp::ZERO; RATE]);
    let (trace, digest) = poseidon_trace(&params, absorb(sample_input()), POSEIDON_LOG_T);
    let air = Poseidon::new(POSEIDON_LOG_T, digest);
    let proof = stark_prove(&air, &trace, QUERIES);
    assert!(stark_verify(&air, &proof, QUERIES), "honest poseidon preimage rejected");
}

#[test]
fn a_wrong_poseidon_digest_is_rejected() {
    let params = Poseidon::new(POSEIDON_LOG_T, [Fp::ZERO; RATE]);
    let (trace, digest) = poseidon_trace(&params, absorb(sample_input()), POSEIDON_LOG_T);
    let wrong = [digest[0] + Fp::ONE, digest[1], digest[2], digest[3]];
    let air = Poseidon::new(POSEIDON_LOG_T, wrong);
    let proof = stark_prove(&air, &trace, QUERIES);
    assert!(!stark_verify(&air, &proof, QUERIES), "a wrong poseidon digest verified");
}

#[test]
fn a_corrupted_poseidon_round_is_rejected() {
    let params = Poseidon::new(POSEIDON_LOG_T, [Fp::ZERO; RATE]);
    let (mut trace, digest) = poseidon_trace(&params, absorb(sample_input()), POSEIDON_LOG_T);
    // Corrupt one lane of a middle row: the round no longer holds there.
    trace[WIDTH * 3 + 2] = trace[WIDTH * 3 + 2] + Fp::ONE;
    let air = Poseidon::new(POSEIDON_LOG_T, digest);
    let proof = stark_prove(&air, &trace, QUERIES);
    assert!(!stark_verify(&air, &proof, QUERIES), "a corrupted poseidon round verified");
}

#[test]
fn a_nonzero_capacity_initialization_is_rejected() {
    // Seeding the capacity with anything but zero computes a different function;
    // the sponge-initialization boundary rejects it.
    let params = Poseidon::new(POSEIDON_LOG_T, [Fp::ZERO; RATE]);
    let mut initial = absorb(sample_input());
    initial[RATE] = Fp::from_u64(5);
    let (trace, digest) = poseidon_trace(&params, initial, POSEIDON_LOG_T);
    let air = Poseidon::new(POSEIDON_LOG_T, digest);
    let proof = stark_prove(&air, &trace, QUERIES);
    assert!(!stark_verify(&air, &proof, QUERIES), "a nonzero capacity init verified");
}

#[test]
fn honest_executions_prove_across_sizes() {
    for log_t in [2u32, 3, 4] {
        let seed = Fp::from_u64(2 + log_t as u64);
        let air = Squaring { log_t, seed };
        let proof = stark_prove(&air, &squaring_trace(log_t, seed), QUERIES);
        assert!(stark_verify(&air, &proof, QUERIES), "squaring at log_t {log_t} rejected");
    }
}

#[test]
fn a_corrupted_squaring_transition_is_rejected() {
    let seed = Fp::from_u64(3);
    let air = Squaring { log_t: 3, seed };
    let mut trace = squaring_trace(3, seed);
    trace[4] = trace[4] + Fp::ONE;
    let proof = stark_prove(&air, &trace, QUERIES);
    assert!(!stark_verify(&air, &proof, QUERIES), "a corrupted squaring verified");
}

#[test]
fn a_corrupted_fibonacci_transition_is_rejected() {
    let air = Fibonacci { log_t: 4 };
    let mut trace = fibonacci_trace(4);
    trace[5] = trace[5] + Fp::ONE;
    let proof = stark_prove(&air, &trace, QUERIES);
    assert!(!stark_verify(&air, &proof, QUERIES), "a corrupted fibonacci verified");
}

#[test]
fn a_corrupted_sbox_step_is_rejected() {
    let (c, start) = (Fp::from_u64(11), Fp::from_u64(2));
    let (mut trace, output) = power_chain_trace(4, start, c);
    trace[6] = trace[6] + Fp::ONE;
    let air = PowerChain { log_t: 4, c, output };
    let proof = stark_prove(&air, &trace, QUERIES);
    assert!(!stark_verify(&air, &proof, QUERIES), "a corrupted s-box step verified");
}

#[test]
fn a_wrong_sbox_output_is_rejected() {
    // The chain is honest, but the claimed public output is wrong.
    let (c, start) = (Fp::from_u64(11), Fp::from_u64(2));
    let (trace, output) = power_chain_trace(4, start, c);
    let air = PowerChain { log_t: 4, c, output: output + Fp::ONE };
    let proof = stark_prove(&air, &trace, QUERIES);
    assert!(!stark_verify(&air, &proof, QUERIES), "a wrong s-box output verified");
}

#[test]
fn a_wrong_boundary_seed_is_rejected() {
    let seed = Fp::from_u64(3);
    let proof = stark_prove(&Squaring { log_t: 3, seed }, &squaring_trace(3, seed), QUERIES);
    let wrong = Squaring { log_t: 3, seed: Fp::from_u64(4) };
    assert!(!stark_verify(&wrong, &proof, QUERIES), "a wrong boundary seed verified");
}

#[test]
fn a_tampered_trace_opening_is_rejected() {
    let seed = Fp::from_u64(3);
    let air = Squaring { log_t: 3, seed };
    let mut proof = stark_prove(&air, &squaring_trace(3, seed), QUERIES);
    proof.queries[0].trace[0] = proof.queries[0].trace[0] + Fp::ONE;
    assert!(!stark_verify(&air, &proof, QUERIES), "a tampered trace opening verified");
}

#[test]
fn a_full_scale_poseidon_preimage_verifies() {
    // The scale check: 256 rounds, a width-8 trace, an evaluation domain of
    // 4096 points. This is the NTT prover at work; the quadratic extension it
    // replaced would not finish this in reasonable test time.
    let log_t = 8u32;
    let params = Poseidon::new(log_t, [Fp::ZERO; RATE]);
    let (trace, digest) = poseidon_trace(&params, absorb(sample_input()), log_t);
    let air = Poseidon::new(log_t, digest);
    let proof = stark_prove(&air, &trace, QUERIES);
    assert!(stark_verify(&air, &proof, QUERIES), "full-scale poseidon preimage rejected");
}

#[test]
fn a_long_squaring_chain_verifies() {
    // A 1024-row single-column trace, domain 4096.
    let seed = Fp::from_u64(3);
    let air = Squaring { log_t: 10, seed };
    let proof = stark_prove(&air, &squaring_trace(10, seed), QUERIES);
    assert!(stark_verify(&air, &proof, QUERIES), "long squaring chain rejected");
}
