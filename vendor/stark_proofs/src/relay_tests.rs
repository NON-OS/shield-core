// NONOS Operating System (AGPL-3.0-or-later)

//! A relayer makes the outer from the wallet's proof and the public words.
//!
//! The wallet proves the inner over its secrets and hands over the proof
//! bytes and the intent, and nothing else. The relayer rebuilds the inner
//! circuit from the intent (`join_split_shape`), packs the wallet's proof
//! against it exactly as the one process prover packs its own, and assembles
//! the outer. If the outer witness assembled that way satisfies the outer
//! AIR, the relayer path is the one process path with the secrets removed
//! from the second half.

use crate::crypto::stark::air::RATE;
use crate::crypto::stark::field::Fp;
use crate::proof_wire::{deserialize_p_rounds, serialize_p_rounds};
use crate::recursion_assembly::inner::{extra, hide, hasher, pack_air, prove_raw, GRIND, NQ};
use crate::recursion_assembly::point::Point;
use crate::recursion_assembly::{assemble_over_wired, Tamper};
use crate::shield::join::join_split_shape;
use crate::shield::live::DEPTH;
use crate::shield::test::shape::published_spend;
use crate::witness_satisfies_public;

#[test]
fn the_outer_assembles_over_the_wallets_proof_and_the_intent_alone() {
    let h = hasher();
    let mut js = published_spend(0x7408_ae4c);
    let intent = js.intent.clone();

    // The wallet's half: a hiding inner proof, serialised for the wire.
    let seed: [Fp; RATE] = core::array::from_fn(|i| Fp::from_u64(0x5eed + i as u64));
    let blind = hide(&h, &mut js, &seed, NQ);
    let proved = prove_raw(&h, js, NQ, GRIND, extra(), &blind);
    assert_eq!(proved.publics, intent, "the inner absorbed the intent as its publics");
    let bytes = serialize_p_rounds(&proved.proof);
    let root = proved.root;
    drop(proved);

    // The relayer's half: the circuit from the intent, the proof from bytes.
    let proof = deserialize_p_rounds(&bytes).expect("the wallet's bytes parse");
    let shape = join_split_shape(DEPTH, &intent);
    let inner = pack_air(&h, shape, proof, intent, root, extra(), GRIND);
    let asm = assemble_over_wired(&h, inner, Tamper::None, 2, Point::emit_wiring());
    assert!(
        witness_satisfies_public(&asm.wired, &asm.witness),
        "the outer assembled by a relayer over the shape does not satisfy"
    );
}
