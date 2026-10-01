// NONOS Operating System (AGPL-3.0-or-later)
//! The relayer's half of a settlement: the outer, from a wallet's inner proof
//! and its public words, with no secret in reach.
//!
//!     relay_settlement <in.inner> <in.inner.intent.json> <out.proof> [root=<hex>] [point=<name>]
//!
//! The inner circuit is rebuilt from the thirty six public words alone
//! (`join_split_shape`, held equal to the wallet's circuit by
//! `shield::test::shape`), the wallet's proof is verified against it before
//! a minute is spent, then packed and folded into the settlement outer the
//! way the one process prover folds its own, and the outer is proved,
//! verified and written by the same code. `relay_tests` is the gate that the
//! outer assembled this way satisfies.

use stark_proofs::crypto::stark::air::{periodic_root_poseidon, stark_verify_poseidon_rounds};
use stark_proofs::crypto::stark::field::Fp;
use stark_proofs::host::{die, pack_u256, point_from_args, prove_outer, read_text, Json};
use stark_proofs::proof_wire::deserialize_p_rounds;
use stark_proofs::recursion_assembly::inner::{self, pack_air, GRIND, NQ};
use stark_proofs::recursion_assembly::point::Point;
use stark_proofs::recursion_assembly::anchors::Anchors;
use stark_proofs::recursion_assembly::{assemble_over_gen_form, Assembly, ComposeForm, Tamper};
use stark_proofs::shield::join::{join_split_shape, INTENT_WORDS};
use stark_proofs::shield::member::TREE_DEPTH;
use stark_proofs::shield_params::inner as inner_point;
use std::time::Instant;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let [inner_path, intent_path, out] = [a.first(), a.get(1), a.get(2)].map(|x| {
        x.cloned().unwrap_or_else(|| {
            die("usage: relay_settlement <in.inner> <in.inner.intent.json> <out.proof> [root=<hex>]")
        })
    });
    let expected_root = a.iter().find_map(|s| s.strip_prefix("root=")).map(str::to_string);
    if inner::extra() != inner_point::EXTRA_BLOWUP_BITS {
        die("the inner must have been proved at the deployment blowup; NONOS_INNER_EXTRA is set and it is refused here");
    }
    assert!(
        Point::emit_rounds(),
        "a one round prover would contradict the layout a verifier was generated from"
    );

    let intent_text = read_text(&intent_path);
    let intent: Vec<Fp> = Json(&intent_text).u64s("publics").into_iter().map(Fp::from_u64).collect();
    if intent.len() != INTENT_WORDS {
        die(&format!("{intent_path}: {} public words, an intent has {INTENT_WORDS}", intent.len()));
    }
    let bytes = std::fs::read(&inner_path).unwrap_or_else(|e| die(&format!("cannot read {inner_path}: {e}")));
    let proof = deserialize_p_rounds(&bytes)
        .unwrap_or_else(|| die(&format!("{inner_path}: not a two round inner proof")));

    let h = inner::hasher();
    let t0 = Instant::now();
    let mut shape = join_split_shape(TREE_DEPTH, &intent);
    let root = periodic_root_poseidon(&shape, inner::extra(), &h);
    println!(
        "circuit   rebuilt from the intent in {:?}, inner periodic root {}",
        t0.elapsed(),
        pack_u256(&root)
    );

    /*
     * The wallet's proof against the rebuilt circuit, before anything is
     * folded. An inner that does not verify would surface twelve minutes
     * later as an outer that does not; this is the cheap place.
     */
    let t1 = Instant::now();
    let ok = stark_verify_poseidon_rounds(&mut shape, &proof, NQ, GRIND, inner::extra(), &h, &intent, &root);
    println!("inner     verified against the rebuilt circuit in {:?}: {ok}", t1.elapsed());
    if !ok {
        die("the inner proof does not verify against the circuit its intent describes; nothing folded");
    }

    let t2 = Instant::now();
    let packed = pack_air(&h, shape, proof, intent, root, inner::extra(), GRIND);
    // The settlement verifier is generated from the program-form outer. An
    // outer assembled any other way has other periodic columns and another root.
    let outer = assemble_over_gen_form(
        &h,
        packed,
        Tamper::None,
        usize::MAX,
        Point::emit_wiring(),
        Anchors::Collapsed,
        ComposeForm::Program,
    );
    let asm = Assembly {
        wired: outer.gen.into_wired(),
        witness: outer.witness,
        lay: outer.lay,
        publics: outer.publics,
        n_groups: outer.n_groups,
        region_offsets: outer.region_offsets,
        kind_bodies: outer.kind_bodies,
    };
    println!("assembled in {:?}", t2.elapsed());
    prove_outer(&h, asm, &out, expected_root.as_deref(), point_from_args(&a));
}
