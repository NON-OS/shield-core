// NONOS Operating System (AGPL-3.0-or-later)
//! Multi-opening membership: batched paths, shared roots, and their faults.

use crate::crypto::stark::air::{
    stark_prove, stark_verify,     MerkleMembership, MultiMembership, Opening, Poseidon, RATE,
};
use crate::crypto::stark::field::Fp;
use crate::crypto::stark::poseidon_merkle::PoseidonMerkleTree;

extern crate alloc;
use alloc::vec::Vec;
#[allow(unused_imports)]
use super::{membership::*, exec::*, poseidon::*, fri::*, fold::*, monolith::*, ext::*, recursive::*, wired::*, fri_fold::*, fri_fused::*, ext_deep::*, fold_chain::*};

#[test]
fn a_measured_capsule_enrolls_and_attests_at_money_grade() {
    use crate::crypto::stark::air::{
        measure_capsule, stark_prove_ext_blown_bound, stark_verify_ext_blown_bound,
    };
    let log_rounds = 3u32;
    let hasher = Poseidon::new(log_rounds, [Fp::ZERO; RATE]);

    let images: [&[u8]; 4] = [
        b"capsule:terminal image bytes",
        b"capsule:net_core image bytes",
        b"capsule:editor image bytes",
        b"capsule:browser image bytes",
    ];
    let leaves: Vec<[Fp; RATE]> = images.iter().map(|img| measure_capsule(&hasher, img)).collect();
    let tree = PoseidonMerkleTree::commit(&hasher, &leaves);
    let root = tree.root();

    let index = 0usize;
    let path = tree.open(index);
    let directions: Vec<bool> = (0..path.len()).map(|k| (index >> k) & 1 == 1).collect();
    let context = b"capsule:terminal:v1";

    // The enrolled capsule attests its own measurement.
    let trace = membership_trace(&hasher, leaves[index], &path, &directions, log_rounds);
    let air =
        MerkleMembership::new(hasher.clone(), log_rounds, root, path.clone(), directions.clone());
    let proof = stark_prove_ext_blown_bound(&air, &trace, 32, 16, 3, context);
    assert!(
        stark_verify_ext_blown_bound(&air, &proof, 32, 16, 3, context),
        "the enrolled measured capsule was rejected"
    );

    // A capsule whose image was never enrolled cannot attest.
    let rogue = measure_capsule(&hasher, b"capsule:rogue never enrolled");
    let rogue_trace = membership_trace(&hasher, rogue, &path, &directions, log_rounds);
    let rogue_proof = stark_prove_ext_blown_bound(&air, &rogue_trace, 32, 16, 3, context);
    assert!(
        !stark_verify_ext_blown_bound(&air, &rogue_proof, 32, 16, 3, context),
        "a rogue capsule measurement attested against the policy root"
    );
}

// The kernel gate's path exactly: a capsule ships a money-grade attestation as
// bytes, the kernel parses it from an untrusted trailer and verifies it bound to the
// capsule identity. The proof survives the round trip, the wrong identity is
// refused, and a truncated trailer parses to nothing rather than panicking.
#[test]
fn a_money_grade_attestation_survives_serialization() {
    use crate::crypto::stark::air::{
        deserialize_proof_ext, measure_capsule, serialize_proof_ext, stark_prove_ext_blown_bound,
        stark_verify_ext_blown_bound,
    };
    let log_rounds = 3u32;
    let hasher = Poseidon::new(log_rounds, [Fp::ZERO; RATE]);
    let images: [&[u8]; 4] =
        [b"capsule:a bytes", b"capsule:b bytes", b"capsule:c bytes", b"capsule:d bytes"];
    let leaves: Vec<[Fp; RATE]> = images.iter().map(|img| measure_capsule(&hasher, img)).collect();
    let tree = PoseidonMerkleTree::commit(&hasher, &leaves);
    let root = tree.root();
    let index = 2usize;
    let path = tree.open(index);
    let directions: Vec<bool> = (0..path.len()).map(|k| (index >> k) & 1 == 1).collect();
    let context = b"capsule:c:v1";

    let trace = membership_trace(&hasher, leaves[index], &path, &directions, log_rounds);
    let air = MerkleMembership::new(hasher.clone(), log_rounds, root, path, directions);
    let proof = stark_prove_ext_blown_bound(&air, &trace, 32, 16, 3, context);

    let bytes = serialize_proof_ext(&proof);
    let parsed = deserialize_proof_ext(&bytes).expect("a valid trailer round-trips");
    assert!(
        stark_verify_ext_blown_bound(&air, &parsed, 32, 16, 3, context),
        "the parsed money-grade attestation was rejected"
    );
    assert!(
        !stark_verify_ext_blown_bound(&air, &parsed, 32, 16, 3, b"capsule:other:v1"),
        "the parsed attestation passed under the wrong identity"
    );
    assert!(
        deserialize_proof_ext(&bytes[..bytes.len() / 2]).is_none(),
        "a truncated trailer parsed instead of failing"
    );
}

// The full loop: the enrollment tool builds a capsule's trailer, and the kernel
// gate's exact parse-and-verify accepts it under the capsule identity and refuses it
// under any other. This is the prover side meeting the verifier side on the same
// byte layout, which is what makes the gate usable end to end.
#[test]
fn a_built_trailer_is_accepted_by_the_gate_logic() {
    use crate::crypto::stark::air::{
        build_attestation_trailer, deserialize_proof_ext, measure_capsule,
        stark_verify_ext_blown_bound, MerkleMembership,
    };
    let log_rounds = 3u32;
    let hasher = Poseidon::new(log_rounds, [Fp::ZERO; RATE]);
    let images: [&[u8]; 4] = [b"cap:a bytes", b"cap:b bytes", b"cap:c bytes", b"cap:d bytes"];
    let index = 1usize;
    let context = b"capsule:b:v1";

    // Tool side.
    let trailer =
        build_attestation_trailer(&hasher, log_rounds, &images, index, context, 32, 16, 3);

    // Kernel side: the same parse the spawn gate runs.
    let depth = trailer[8] as usize;
    let mut siblings = Vec::with_capacity(depth);
    for i in 0..depth {
        let mut s = [Fp::ZERO; RATE];
        for (j, lane) in s.iter_mut().enumerate() {
            let mut w = [0u8; 8];
            w.copy_from_slice(&trailer[9 + i * 32 + j * 8..9 + i * 32 + j * 8 + 8]);
            *lane = Fp::from_u64(u64::from_le_bytes(w));
        }
        siblings.push(s);
    }
    let sib_end = 9 + depth * 32;
    let dir_bytes = depth.div_ceil(8);
    let dirs = &trailer[sib_end..sib_end + dir_bytes];
    let directions: Vec<bool> = (0..depth).map(|i| (dirs[i / 8] >> (i % 8)) & 1 == 1).collect();
    let proof = deserialize_proof_ext(&trailer[sib_end + dir_bytes..]).expect("the proof parses");

    // The kernel's own policy root, which enrollment publishes.
    let leaves: Vec<[Fp; RATE]> = images.iter().map(|i| measure_capsule(&hasher, i)).collect();
    let root = PoseidonMerkleTree::commit(&hasher, &leaves).root();
    let air = MerkleMembership::new(hasher.clone(), log_rounds, root, siblings, directions);

    assert!(
        stark_verify_ext_blown_bound(&air, &proof, 32, 16, 3, context),
        "a tool-built trailer was rejected by the gate logic"
    );
    assert!(
        !stark_verify_ext_blown_bound(&air, &proof, 32, 16, 3, b"capsule:evil:v1"),
        "the trailer passed under the wrong capsule identity"
    );
}

// The shared verify core, exercised the way the kernel self-attestation calls it:
// a kernel image is measured into the context, a trailer proves its measurement is
// enrolled under the trust root, and the core accepts it and refuses a foreign boot
// context. Same path the capsule gate uses, one layer up.
#[test]
fn the_shared_verify_core_accepts_a_kernel_self_attestation() {
    use crate::crypto::stark::air::{
        build_attestation_trailer, measure_capsule, verify_membership_trailer, RATE,
    };
    let log_rounds = 3u32;
    let hasher = Poseidon::new(log_rounds, [Fp::ZERO; RATE]);
    // The enrolled kernel image plus a few others, its measurement in the root.
    let images: [&[u8]; 4] = [b"nonos-kernel image", b"other:a", b"other:b", b"other:c"];
    let index = 0usize;
    let boot_ctx = b"kernel:boot:epoch:1";

    let trailer =
        build_attestation_trailer(&hasher, log_rounds, &images, index, boot_ctx, 32, 16, 3);

    // The trust root the boot chain carries, as 32 bytes.
    let leaves: Vec<[Fp; RATE]> = images.iter().map(|i| measure_capsule(&hasher, i)).collect();
    let root_rate = PoseidonMerkleTree::commit(&hasher, &leaves).root();
    let mut root = [0u8; 32];
    for (i, lane) in root_rate.iter().enumerate() {
        root[i * 8..i * 8 + 8].copy_from_slice(&lane.value().to_le_bytes());
    }

    let depth = trailer[8] as usize;
    assert!(
        verify_membership_trailer(&hasher, log_rounds, root, depth, &trailer, boot_ctx, 32, 16, 3),
        "the kernel self-attestation was rejected by the shared core"
    );
    assert!(
        !verify_membership_trailer(
            &hasher,
            log_rounds,
            root,
            depth,
            &trailer,
            b"kernel:boot:epoch:2",
            32,
            16,
            3
        ),
        "a self-attestation passed under the wrong boot context"
    );
}

#[test]
fn membership_proofs_verify_at_fri_layer_depths() {
    // FRI layers are sized 2^k, so paths are depth k, any value. The AIR pads its
    // slots to a power of two, so an opening from a FRI-sized layer (depth 5, the
    // same Poseidon commitment the recursion-ready FRI uses) proves in a STARK.
    let log_rounds = 3u32;
    let hasher = Poseidon::new(log_rounds, [Fp::ZERO; RATE]);
    for &(count, index) in &[(16usize, 9usize), (32, 21), (64, 40)] {
        assert!(
            prove_membership(&hasher, &merkle_leaves(count), index, log_rounds),
            "membership at a {count}-leaf layer rejected"
        );
    }
}

/// Build the batched trace: each opening runs its Merkle path, then the state
/// resets to the next opening's leaf; padding openings run freely.
pub(super) fn opening_at(tree: &PoseidonMerkleTree, leaves: &[[Fp; RATE]], index: usize) -> Opening {
    let path = tree.open(index);
    let directions = (0..path.len()).map(|k| (index >> k) & 1 == 1).collect();
    Opening { leaf: leaves[index], root: tree.root(), siblings: path, directions }
}

#[test]
fn a_batched_opening_proof_verifies() {
    // Verify two openings of one FRI layer (the a and b a query reads) in a
    // single STARK: the heavy half of a FRI query verifier.
    let log_rounds = 3u32;
    let hasher = Poseidon::new(log_rounds, [Fp::ZERO; RATE]);
    let leaves = merkle_leaves(8);
    let tree = PoseidonMerkleTree::commit(&hasher, &leaves);
    let openings = alloc::vec![opening_at(&tree, &leaves, 2), opening_at(&tree, &leaves, 6)];
    let air = MultiMembership::new(hasher.clone(), log_rounds, openings);
    let trace = air.trace();
    let proof = stark_prove(&air, &trace, QUERIES);
    assert!(stark_verify(&air, &proof, QUERIES), "a batched opening proof was rejected");
}

#[test]
fn a_batched_opening_with_a_wrong_root_is_rejected() {
    let log_rounds = 3u32;
    let hasher = Poseidon::new(log_rounds, [Fp::ZERO; RATE]);
    let leaves = merkle_leaves(8);
    let tree = PoseidonMerkleTree::commit(&hasher, &leaves);
    let mut o0 = opening_at(&tree, &leaves, 2);
    let o1 = opening_at(&tree, &leaves, 6);
    o0.root[0] = o0.root[0] + Fp::ONE; // corrupt the first opening's claimed root
    let air = MultiMembership::new(hasher.clone(), log_rounds, alloc::vec![o0, o1]);
    // The trace hashes the true leaves and siblings, so its checkpoint holds the
    // real root while the boundary pins the corrupted one: a mismatch.
    let trace = air.trace();
    let proof = stark_prove(&air, &trace, QUERIES);
    assert!(!stark_verify(&air, &proof, QUERIES), "a wrong batched root verified");
}
