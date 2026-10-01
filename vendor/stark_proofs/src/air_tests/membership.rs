// NONOS Operating System (AGPL-3.0-or-later)

use crate::crypto::stark::air::{
    stark_prove, stark_verify,     MerkleMembership, Poseidon, RATE, WIDTH,
};
use crate::crypto::stark::field::Fp;
use crate::crypto::stark::poseidon_merkle::PoseidonMerkleTree;

extern crate alloc;
use alloc::vec::Vec;
#[allow(unused_imports)]
use super::{exec::*, poseidon::*, fri::*, fold::*, monolith::*, ext::*, recursive::*, wired::*, fri_fold::*, fri_fused::*, ext_deep::*, fold_chain::*, membership_multi::*};

pub(super) fn inject(node: [Fp; RATE], sibling: [Fp; RATE], right: bool) -> [Fp; WIDTH] {
    let mut state = [Fp::ZERO; WIDTH];
    if !right {
        state[..RATE].copy_from_slice(&node);
        state[RATE..].copy_from_slice(&sibling);
    } else {
        state[..RATE].copy_from_slice(&sibling);
        state[RATE..].copy_from_slice(&node);
    }
    state
}

/// Build the Poseidon-state trace of a Merkle path of any depth: compress the
/// node with each sibling by the index bit, place the root at the checkpoint,
/// and let any padding slots run the permutation freely.
pub(super) fn membership_trace(
    hasher: &Poseidon,
    leaf: [Fp; RATE],
    siblings: &[[Fp; RATE]],
    directions: &[bool],
    log_rounds: u32,
) -> Vec<Fp> {
    let l = 1usize << log_rounds;
    let depth = siblings.len();
    // Matches MerkleMembership: a slot per level plus the root, unpadded, then
    // the trace padded up to a power of two.
    let n = ((depth + 1) * l).next_power_of_two();

    let mut rows: Vec<[Fp; WIDTH]> = Vec::with_capacity(n);
    let mut state = inject(leaf, siblings[0], directions[0]);
    for r in 0..n {
        rows.push(state);
        let pr = hasher.round_with_rc(&state, &hasher.round_constant(r % l));
        if r % l == l - 1 && r < depth * l {
            let m = (r + 1) / l;
            let mut node = [Fp::ZERO; RATE];
            node.copy_from_slice(&pr[..RATE]);
            if m < depth {
                state = inject(node, siblings[m], directions[m]);
            } else {
                state = inject(node, [Fp::ZERO; RATE], false);
            }
        } else {
            state = pr;
        }
    }

    let mut trace = Vec::with_capacity(n * WIDTH);
    for row in &rows {
        trace.extend_from_slice(row);
    }
    trace
}

pub(super) fn merkle_leaves(n: usize) -> Vec<[Fp; RATE]> {
    (0..n)
        .map(|i| {
            let mut d = [Fp::ZERO; RATE];
            for (c, cell) in d.iter_mut().enumerate() {
                *cell = Fp::from_u64((i * RATE + c + 1) as u64);
            }
            d
        })
        .collect()
}

pub(super) fn prove_membership(
    hasher: &Poseidon,
    leaves: &[[Fp; RATE]],
    index: usize,
    log_rounds: u32,
) -> bool {
    let tree = PoseidonMerkleTree::commit(hasher, leaves);
    let root = tree.root();
    let path = tree.open(index);
    let directions: Vec<bool> = (0..path.len()).map(|k| (index >> k) & 1 == 1).collect();
    let trace = membership_trace(hasher, leaves[index], &path, &directions, log_rounds);
    let air = MerkleMembership::new(hasher.clone(), log_rounds, root, path, directions);
    let proof = stark_prove(&air, &trace, QUERIES);
    stark_verify(&air, &proof, QUERIES)
}

#[test]
fn a_merkle_membership_proof_verifies() {
    // Prove, inside a STARK, that a leaf opens to a public Poseidon Merkle root:
    // the commitment check is now itself a proof, the core recursion step.
    let log_rounds = 3u32; // 8-round hash
    let hasher = Poseidon::new(log_rounds, [Fp::ZERO; RATE]);
    assert!(prove_membership(&hasher, &merkle_leaves(8), 5, log_rounds), "membership rejected");
}

// The capsule attestation gate, end to end. Enroll a set of capsule measurements
// into a policy root, prove membership bound to the capsule identity, serialize the
// proof, and gate on the kernel's verify_membership_attestation. A proof passes only
// under the identity it was drawn for and only against the enrolled root, so a
// forged identity or a foreign root is refused. This is the attestation a spawn
// gates on: the leaf (the capsule secret) stays private, the path is public.
#[test]
fn the_capsule_attestation_gate_accepts_enrolled_and_rejects_forged() {
    use crate::crypto::stark::air::{
        serialize_proof, stark_prove_bound, verify_membership_attestation,
    };
    let log_rounds = 3u32;
    let hasher = Poseidon::new(log_rounds, [Fp::ZERO; RATE]);

    // The enrolled capsule measurements, committed to the kernel's policy root.
    let leaves = merkle_leaves(8);
    let tree = PoseidonMerkleTree::commit(&hasher, &leaves);
    let root = tree.root();

    // This capsule sits at slot 5; its identity binds the attestation.
    let index = 5usize;
    let path = tree.open(index);
    let directions: Vec<bool> = (0..path.len()).map(|k| (index >> k) & 1 == 1).collect();
    let context = b"capsule:terminal:v1";

    // Enrollment proves knowledge of the enrolled leaf, bound to the identity.
    let trace = membership_trace(&hasher, leaves[index], &path, &directions, log_rounds);
    let air =
        MerkleMembership::new(hasher.clone(), log_rounds, root, path.clone(), directions.clone());
    let proof = stark_prove_bound(&air, &trace, QUERIES, context);
    let bytes = serialize_proof(&proof);

    // The kernel gate accepts the enrolled capsule under its own identity.
    assert!(
        verify_membership_attestation(
            &hasher,
            log_rounds,
            root,
            &path,
            &directions,
            QUERIES,
            &bytes,
            context
        ),
        "an enrolled capsule attestation was rejected"
    );
    // The same proof presented under a different identity is refused.
    assert!(
        !verify_membership_attestation(
            &hasher,
            log_rounds,
            root,
            &path,
            &directions,
            QUERIES,
            &bytes,
            b"capsule:impostor"
        ),
        "an attestation passed under the wrong capsule identity"
    );
    // A foreign policy root is refused.
    let mut bad_root = root;
    bad_root[0] = bad_root[0] + Fp::from_u64(1);
    assert!(
        !verify_membership_attestation(
            &hasher,
            log_rounds,
            bad_root,
            &path,
            &directions,
            QUERIES,
            &bytes,
            context
        ),
        "an attestation passed against a forged policy root"
    );
}

// The production-strength attestation: the same membership gate proven at
// money-grade soundness (extension-field challenges, rate one sixteenth, grinding)
// and bound to the capsule identity. The base gate is a demonstration rate; this is
// the ~128-bit gate a spawn can actually rely on, and it still refuses a foreign
// identity.
#[test]
fn the_capsule_attestation_holds_at_money_grade_soundness() {
    use crate::crypto::stark::air::{stark_prove_ext_blown_bound, stark_verify_ext_blown_bound};
    let log_rounds = 3u32;
    let hasher = Poseidon::new(log_rounds, [Fp::ZERO; RATE]);
    let leaves = merkle_leaves(8);
    let tree = PoseidonMerkleTree::commit(&hasher, &leaves);
    let root = tree.root();
    let index = 5usize;
    let path = tree.open(index);
    let directions: Vec<bool> = (0..path.len()).map(|k| (index >> k) & 1 == 1).collect();
    let context = b"capsule:terminal:v1";

    let trace = membership_trace(&hasher, leaves[index], &path, &directions, log_rounds);
    let air = MerkleMembership::new(hasher.clone(), log_rounds, root, path, directions);
    // Rate one sixteenth, 32 queries, 16 grinding bits: ~128-bit conjectured.
    let proof = stark_prove_ext_blown_bound(&air, &trace, 32, 16, 3, context);
    assert!(
        stark_verify_ext_blown_bound(&air, &proof, 32, 16, 3, context),
        "the money-grade attestation was rejected under its own identity"
    );
    assert!(
        !stark_verify_ext_blown_bound(&air, &proof, 32, 16, 3, b"capsule:impostor"),
        "the money-grade attestation passed under the wrong identity"
    );
}

// The whole gate on real inputs: measure actual capsule images to Poseidon leaves,
// enroll them into the policy root, and let a capsule attest its own measurement at
// money-grade soundness bound to its identity. A capsule whose image was never
// enrolled cannot attest, because its measurement reaches no path to the root. This
// is what makes the leaves mean something: enrollment is measurement, not an
// arbitrary secret.
