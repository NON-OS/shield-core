// NONOS Operating System (AGPL-3.0-or-later)

use super::fixture::hasher;
use crate::crypto::stark::air::{NOTE_DOMAIN, NOTE_LIMBS, RATE};
use crate::crypto::stark::field::Fp;

fn one_to_eleven() -> [Fp; NOTE_LIMBS] {
    core::array::from_fn(|i| Fp::from_u64(i as u64 + 1))
}

/// The permutation, pinned on its own. Determinism and binding hold for any
/// self consistent hash, so without this a change to the round function
/// surfaces only downstream, after notes exist. Separate from the commitment
/// pin below so a change to the permutation cannot ride in behind a change to
/// the layout. Do not re-baseline.
#[test]
fn the_permutation_is_frozen_to_the_deployed_digest() {
    let a: [Fp; RATE] = core::array::from_fn(|i| Fp::from_u64(i as u64 + 1));
    let b: [Fp; RATE] = core::array::from_fn(|i| Fp::from_u64(i as u64 + 5));
    let want: [u64; RATE] = [
        1022089083010806312,
        8134804760473441809,
        13972665140821454643,
        18290724068579387637,
    ];
    assert_eq!(hasher().compress(&a, &b).map(|v| v.value()), want);
}

/// The known answers a second implementation is pointed at (paper, Appendix
/// C): all eight lanes of the permutation of one through eight, the rate-only
/// sponge over thirty one rounds, the first round constant and the first entry
/// of the diffusion matrix, read off one round of a unit vector. Do not
/// re-baseline.
#[test]
fn the_published_known_answers_hold() {
    let h = hasher();
    let state: [Fp; 8] = core::array::from_fn(|i| Fp::from_u64(i as u64 + 1));
    let want: [u64; 8] = [
        1022089083010806312,
        8134804760473441809,
        13972665140821454643,
        18290724068579387637,
        33538716422518085,
        4874145967630906442,
        3176566405087518195,
        7617985140508846139,
    ];
    assert_eq!(h.permute(state).map(|v| v.value()), want);
    let rate: [Fp; RATE] = core::array::from_fn(|i| Fp::from_u64(i as u64 + 1));
    let want: [u64; RATE] = [
        2169049970631926957,
        6775483557278429577,
        12065499352586199786,
        5346927755136647619,
    ];
    assert_eq!(h.hash(&rate).map(|v| v.value()), want);
    let rc = h.round_constant(0)[0];
    assert_eq!(rc.value(), 1416716216247504991);
    let mut unit = [Fp::ZERO; 8];
    unit[0] = Fp::ONE;
    assert_eq!((h.round(&unit, 0)[0] - rc).value(), 2305843008676823040);
}

/// The note commitment, which PoseidonGoldilocks.commitNote is gated against.
/// This pin moves when the layout of the commitment moves and only then.
/// Re-baseline from `emit_key_vector`, never by hand.
#[test]
fn the_pool_hash_is_frozen_to_the_deployed_digest() {
    let want: [u64; RATE] = [
        3128788525238172940,
        977760251882506394,
        7248597715382424175,
        11116448888154628040,
    ];
    let got = hasher().commit_note(&one_to_eleven());
    assert_eq!(got.map(|v| v.value()), want);
}

/// The public half and the secret half do not share a compression, which is
/// what lets a pool build the leaf from the amount it escrowed while the owner
/// half stays a preimage to it.
#[test]
fn the_commitment_nests_the_owner_under_the_public_quad() {
    let h = hasher();
    let limbs = one_to_eleven();
    let spend_pk: [Fp; RATE] = core::array::from_fn(|i| limbs[3 + i]);
    let blinding: [Fp; RATE] = core::array::from_fn(|i| limbs[7 + i]);
    let owner = h.commit_owner(&spend_pk, &blinding);
    let public = [limbs[0], limbs[1], limbs[2], Fp::from_u64(NOTE_DOMAIN)];
    assert_eq!(h.compress(&public, &owner), h.commit_note(&limbs));
}
