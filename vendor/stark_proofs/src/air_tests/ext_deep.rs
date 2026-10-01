// NONOS Operating System (AGPL-3.0-or-later)
//! The extension DEEP and composition checks.

use crate::crypto::stark::air::{
        Poseidon, RATE,
};
use crate::crypto::stark::field::Fp;

extern crate alloc;
#[allow(unused_imports)]
use super::{ext::*, exec::*, poseidon::*, membership::*, fri::*, fold::*, monolith::*, recursive::*, wired::*, fri_fold::*, fri_fused::*, fold_chain::*, membership_multi::*};

#[test]
fn the_money_grade_stark_proves_a_value_in_range() {
    use crate::crypto::stark::air::{stark_prove_ext, stark_verify_ext, RangeCheck};
    let air = RangeCheck { log_t: 4 }; // bound 2^15
    let proof = stark_prove_ext(&air, &range_trace(12345, 4), 32, 8);
    assert!(stark_verify_ext(&air, &proof, 32, 8), "an in-range value was rejected");
}

#[test]
fn the_money_grade_stark_rejects_an_out_of_range_value() {
    use crate::crypto::stark::air::{stark_prove_ext, stark_verify_ext, RangeCheck};
    let air = RangeCheck { log_t: 4 };
    let proof = stark_prove_ext(&air, &range_trace(1u64 << 15, 4), 32, 8);
    assert!(!stark_verify_ext(&air, &proof, 32, 8), "an out-of-range value verified");
}

// The money-grade fusion: two independent constraint systems (value conservation
// AND range) proven as ONE STARK, each region's constraints firing under its
// selector. This is the composition shape of the full join-split proof; the honest
// compound trace verifies, and breaking either region is rejected.
#[test]
fn the_money_grade_stark_fuses_conservation_and_range() {
    use crate::crypto::stark::air::{
        stark_prove_ext, stark_verify_ext, Accumulator, AirExt, FusedExt, RangeCheck,
    };
    use alloc::boxed::Box;
    let regions: alloc::vec::Vec<Box<dyn AirExt>> = alloc::vec![
        Box::new(Accumulator { log_t: 3 }) as Box<dyn AirExt>,
        Box::new(RangeCheck { log_t: 4 })
    ];
    let fused = FusedExt::new(regions);
    let addends =
        [Fp::from_u64(7), Fp::from_u64(3), neg(8), neg(1), neg(1), Fp::ZERO, Fp::ZERO, Fp::ZERO];
    let cons = accumulator_trace(&addends);
    let rng = range_trace(12345, 4);
    let trace = fused.trace(&[cons, rng]);
    let proof = stark_prove_ext(&fused, &trace, 32, 8);
    assert!(stark_verify_ext(&fused, &proof, 32, 8), "an honest fused compound proof was rejected");
}

#[test]
fn the_fused_money_grade_stark_rejects_a_broken_region() {
    use crate::crypto::stark::air::{
        stark_prove_ext, stark_verify_ext, Accumulator, AirExt, FusedExt, RangeCheck,
    };
    use alloc::boxed::Box;
    let regions: alloc::vec::Vec<Box<dyn AirExt>> = alloc::vec![
        Box::new(Accumulator { log_t: 3 }) as Box<dyn AirExt>,
        Box::new(RangeCheck { log_t: 4 })
    ];
    let fused = FusedExt::new(regions);
    // Conservation broken (addends do not cancel), range fine.
    let addends =
        [Fp::from_u64(7), Fp::from_u64(3), neg(8), neg(1), Fp::ZERO, Fp::ZERO, Fp::ZERO, Fp::ZERO];
    let cons = accumulator_trace(&addends);
    let rng = range_trace(12345, 4);
    let trace = fused.trace(&[cons, rng]);
    let proof = stark_prove_ext(&fused, &trace, 32, 8);
    assert!(
        !stark_verify_ext(&fused, &proof, 32, 8),
        "a fused proof with a broken region verified"
    );
}

// The join-split CORE as ONE money-grade STARK: value conservation AND range AND a
// private membership opening, three real regions fused and proven together at
// ~2^-128. This is the compound shape the pool's settlement proves (nullifier and
// commitment are the same Poseidon primitive; copy-constraint wiring binds the
// shared value). Honest compound witness verifies.
#[test]
fn the_money_grade_stark_proves_the_join_split_core() {
    use crate::crypto::stark::air::{
        stark_prove_ext, stark_verify_ext, Accumulator, AirExt, FusedExt, MerkleMembership,
        RangeCheck,
    };
    use crate::crypto::stark::poseidon_merkle::PoseidonMerkleTree;
    use alloc::boxed::Box;

    let log_rounds = 3u32;
    let hasher = Poseidon::new(log_rounds, [Fp::ZERO; RATE]);
    let leaves = merkle_leaves(8);
    let index = 5usize;
    let tree = PoseidonMerkleTree::commit(&hasher, &leaves);
    let root = tree.root();
    let path = tree.open(index);
    let directions: alloc::vec::Vec<bool> =
        (0..path.len()).map(|k| (index >> k) & 1 == 1).collect();
    let mem_trace = membership_trace(&hasher, leaves[index], &path, &directions, log_rounds);
    let mem_air = MerkleMembership::new(hasher.clone(), log_rounds, root, path, directions);

    let regions: alloc::vec::Vec<Box<dyn AirExt>> = alloc::vec![
        Box::new(Accumulator { log_t: 3 }) as Box<dyn AirExt>,
        Box::new(RangeCheck { log_t: 4 }),
        Box::new(mem_air),
    ];
    let fused = FusedExt::new(regions);

    let addends =
        [Fp::from_u64(7), Fp::from_u64(3), neg(8), neg(1), neg(1), Fp::ZERO, Fp::ZERO, Fp::ZERO];
    let cons = accumulator_trace(&addends);
    let rng = range_trace(12345, 4);
    let trace = fused.trace(&[cons, rng, mem_trace]);

    let proof = stark_prove_ext(&fused, &trace, 32, 8);
    assert!(stark_verify_ext(&fused, &proof, 32, 8), "the join-split core proof was rejected");
}

// A money-grade WIRED binding: region A produces a value, region B starts from it,
// and a copy constraint forces A's last cell equal to B's first, so the two
// internally-valid regions must agree on the shared value -- all at ~2^-128. This
// is how the join-split binds one note's value across its conservation, range, and
// commitment regions. Honest binding verifies; a mismatched handoff is rejected.
#[test]
fn the_money_grade_stark_wires_a_shared_value() {
    use crate::crypto::stark::air::{
        stark_prove_ext, stark_verify_ext, AirExt, Squaring, WiredExt,
    };
    use alloc::boxed::Box;
    let a_trace = squaring_trace(3, Fp::from_u64(3));
    let handoff = a_trace[7];
    let b_trace = squaring_trace(3, handoff);
    let mut sigma: alloc::vec::Vec<usize> = (0..16).collect();
    sigma.swap(7, 8); // A's last cell wired to B's first
    let regions: alloc::vec::Vec<Box<dyn AirExt>> = alloc::vec![
        Box::new(Squaring { log_t: 3, seed: Fp::from_u64(3) }) as Box<dyn AirExt>,
        Box::new(Squaring { log_t: 3, seed: handoff }),
    ];
    let wired = WiredExt::new(regions, alloc::vec![0], sigma, Fp::from_u64(5), Fp::from_u64(7));
    let witness = wired.trace(&[a_trace, b_trace]);
    let proof = stark_prove_ext(&wired, &witness, 32, 8);
    assert!(stark_verify_ext(&wired, &proof, 32, 8), "an honest money-grade wiring was rejected");
}

#[test]
fn the_money_grade_stark_rejects_a_broken_wire() {
    use crate::crypto::stark::air::{
        stark_prove_ext, stark_verify_ext, AirExt, Squaring, WiredExt,
    };
    use alloc::boxed::Box;
    let a_trace = squaring_trace(3, Fp::from_u64(3));
    let b_trace = squaring_trace(3, Fp::from_u64(99)); // B starts from a DIFFERENT value
    let mut sigma: alloc::vec::Vec<usize> = (0..16).collect();
    sigma.swap(7, 8);
    let regions: alloc::vec::Vec<Box<dyn AirExt>> = alloc::vec![
        Box::new(Squaring { log_t: 3, seed: Fp::from_u64(3) }) as Box<dyn AirExt>,
        Box::new(Squaring { log_t: 3, seed: Fp::from_u64(99) }),
    ];
    let wired = WiredExt::new(regions, alloc::vec![0], sigma, Fp::from_u64(5), Fp::from_u64(7));
    let witness = wired.trace(&[a_trace, b_trace]);
    let proof = stark_prove_ext(&wired, &witness, 32, 8);
    assert!(!stark_verify_ext(&wired, &proof, 32, 8), "a broken money-grade wire verified");
}

// A WIRED join-split at money-grade: value conservation AND range on the value AND
// a copy constraint binding conservation's input to the range-checked value, so
// they must be the SAME note value (not two independent statements). This is the
// real join-split shape. Honest verifies; unbinding the value is rejected.
#[test]
fn the_money_grade_stark_proves_a_wired_join_split() {
    use crate::crypto::stark::air::{
        stark_prove_ext, stark_verify_ext, Accumulator, AirExt, RangeCheck, WiredExt,
    };
    use alloc::boxed::Box;
    let regions: alloc::vec::Vec<Box<dyn AirExt>> = alloc::vec![
        Box::new(Accumulator { log_t: 3 }) as Box<dyn AirExt>,
        Box::new(RangeCheck { log_t: 4 }),
    ];
    // span = (8 + 16).next_pow2() = 32. Wire col 0: conservation acc[1] (fused row 1,
    // = the input 7) bound to range acc[0] (fused row 8, the range-checked value).
    let mut sigma: alloc::vec::Vec<usize> = (0..32).collect();
    sigma.swap(1, 8);
    let wired = WiredExt::new(regions, alloc::vec![0], sigma, Fp::from_u64(5), Fp::from_u64(7));
    let addends =
        [Fp::from_u64(7), Fp::from_u64(3), neg(8), neg(1), neg(1), Fp::ZERO, Fp::ZERO, Fp::ZERO];
    let cons = accumulator_trace(&addends); // acc[1] = 7
    let rng = range_trace(7, 4); // range-checks 7
    let witness = wired.trace(&[cons, rng]);
    let proof = stark_prove_ext(&wired, &witness, 32, 8);
    assert!(stark_verify_ext(&wired, &proof, 32, 8), "an honest wired join-split was rejected");
}

#[test]
fn the_wired_join_split_rejects_an_unbound_value() {
    use crate::crypto::stark::air::{
        stark_prove_ext, stark_verify_ext, Accumulator, AirExt, RangeCheck, WiredExt,
    };
    use alloc::boxed::Box;
    let regions: alloc::vec::Vec<Box<dyn AirExt>> = alloc::vec![
        Box::new(Accumulator { log_t: 3 }) as Box<dyn AirExt>,
        Box::new(RangeCheck { log_t: 4 }),
    ];
    let mut sigma: alloc::vec::Vec<usize> = (0..32).collect();
    sigma.swap(1, 8);
    let wired = WiredExt::new(regions, alloc::vec![0], sigma, Fp::from_u64(5), Fp::from_u64(7));
    let addends =
        [Fp::from_u64(7), Fp::from_u64(3), neg(8), neg(1), neg(1), Fp::ZERO, Fp::ZERO, Fp::ZERO];
    let cons = accumulator_trace(&addends); // acc[1] = 7
    let rng = range_trace(9999, 4); // range-checks a DIFFERENT value
    let witness = wired.trace(&[cons, rng]);
    let proof = stark_prove_ext(&wired, &witness, 32, 8);
    assert!(!stark_verify_ext(&wired, &proof, 32, 8), "an unbound wired join-split verified");
}
