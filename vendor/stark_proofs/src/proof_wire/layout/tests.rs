// NONOS Operating System (AGPL-3.0-or-later)
//! The layout is checked against one real artifact and against the two
//! arithmetic errors that a real artifact caught. Both mutations are the
//! historical bugs restored: if either passes, this module has stopped being
//! able to detect the thing it was written for.

use super::super::header::ParamSet;
use super::geometry::Layout;
use alloc::vec::Vec;

/// The shipped point's geometry at format 5.
///
/// settlement-onetx.proof, 2026-09-22, was 112,436 bytes at these parameters,
/// and the layout closed on it byte for byte (sha256 92479a55...3760, kept
/// outside the repository with its provenance). Format 5 takes the
/// DEEP root and every query's DEEP opening off the wire: 24 bytes, and
/// 12 x 716 for the openings (four values, a count, a path of 27 digests),
/// so the same parameters now end 8,616 bytes sooner. What is pinned is the
/// shape, because a layout change should produce a loud diff in this file
/// rather than a quiet one in the chain's reads.
const SHIPPED_LEN: usize = 103_820;

/// `n_boundary` is recovered, not read: the prover publishes z, the contract's
/// transcript replay lands on it for exactly one composition-coefficient count,
/// 760, and 760 less the 37 transitions is 723 boundaries. An earlier revision
/// of this fixture said 3, which was a guess, and moved the pinned identity.
fn shipped() -> ParamSet {
    ParamSet {
        n_queries: 12,
        grind_bits: 32,
        extra_blowup_bits: 7,
        fri_fold_log: 2,
        fri_stop_log: 8,
        digest_bytes: 24,
        trace_width: 41,
        n_periodic: 119,
        log_trace_len: 18,
        constraint_degree: 8,
        window_size: 2,
        num_transition: 37,
        n_boundary: 723,
        coset_shift: 7,
        commit_grind_bits: 0,
        grind_chunks: 1,
    }
}

#[test]
fn the_shipped_artifact_ends_where_the_layout_says() {
    let l = Layout::of(&shipped());
    assert_eq!(l.log_domain, 29, "the domain is derived, not read");
    assert_eq!(l.tree_depth, 29, "a tree over 2^LN points has depth LN");
    assert_eq!(l.fri_layers, 6);
    assert_eq!(l.n_final, 512);
    assert_eq!(l.n_ood, 82);
    assert_eq!(
        (0..6).map(|m| l.fri_depth(m)).collect::<Vec<_>>(),
        [27, 25, 23, 21, 19, 17],
        "FRI depth is LN - fold * (m + 1)"
    );
    assert_eq!(l.fri.stride, 3_580, "fri query stride");
    assert_eq!(
        l.cons.stride, 1_748,
        "consistency stride: 2,464 at format 4, less the 716-byte DEEP opening"
    );
    assert_eq!(l.sidecar.stride, 1_652, "sidecar stride");
    assert_eq!(l.perm.stride, 700, "permutation stride");
    assert_eq!(l.fri.base, 9_736, "9,760 at format 4, less the DEEP root");
    assert_eq!(l.cons.base, 52_708);
    assert_eq!(l.sidecar.base, 73_688);
    assert_eq!(l.perm.base, 95_420);
    assert_eq!(l.end, SHIPPED_LEN);
    l.chain_closes(SHIPPED_LEN)
        .expect("the section chain must close");
}

/// The first of the two historical errors: the FRI depth written one too
/// shallow. It was issued as a correction to a table that was right, and it
/// would have moved every FRI path read by 24 bytes and compounding.
#[test]
fn the_fri_depth_off_by_one_does_not_close() {
    let p = shipped();
    let l = Layout::of(&p);
    let dg = p.digest_bytes as usize;
    let wrong: usize = (0..l.fri_layers)
        .map(|m| 16 * 4 + 4 + dg * (l.log_domain as usize - 3 - 2 * m))
        .sum::<usize>()
        + 4;
    assert_ne!(
        wrong, l.fri.stride,
        "LN - 3 - 2m must not reproduce the stride"
    );
    let shifted = l.end - (l.fri.stride - wrong) * p.n_queries as usize;
    assert_ne!(
        shifted, SHIPPED_LEN,
        "the off-by-one must not end on the last byte"
    );
}

/// The second: the consistency stride with a phantom length prefix, 56
/// against the true 48, written when the section still carried the DEEP
/// opening. It must stay unreachable at every format.
#[test]
fn the_consistency_stride_with_a_phantom_prefix_does_not_close() {
    let p = shipped();
    let l = Layout::of(&p);
    let w = p.trace_width as usize;
    let d = l.tree_depth;
    let wrong = 56 + 8 * w + 72 * d;
    assert_eq!(wrong, 2_472, "the error as it was written");
    assert_ne!(wrong, l.cons.stride);
    let shifted = l.end + (wrong - l.cons.stride) * p.n_queries as usize;
    assert_ne!(
        shifted, SHIPPED_LEN,
        "the phantom prefix must not end on the last byte"
    );
}

/// The third historical error, the one that caused the other two: a domain
/// size supplied rather than derived. There is no way to supply it, so the
/// test is that the wrong value cannot be reached from the parameters.
#[test]
fn the_domain_cannot_be_supplied() {
    let l = Layout::of(&shipped());
    assert_ne!(
        l.log_domain, 30,
        "LN 30 came from a tool printing depth + 1"
    );
    assert_eq!(l.log_domain, Layout::log_domain_of(&shipped()));
    assert_eq!(
        l.tree_depth, l.log_domain as usize,
        "non-FRI depth is LN, not LN - 1"
    );
}

/// The manifest is what a verifier generator consumes, so its identity has
/// to move whenever any offset does. Three mutations, one per class: a
/// section base, a stride, and a FRI layer's depth.
#[test]
fn the_layout_identity_moves_with_every_offset() {
    let base = Layout::of(&shipped());
    let id = base.id();

    let mut p = shipped();
    p.n_queries += 1;
    assert_ne!(
        Layout::of(&p).id(),
        id,
        "a query count change must move the geometry"
    );

    let mut p = shipped();
    p.trace_width += 1;
    assert_ne!(
        Layout::of(&p).id(),
        id,
        "a trace width change must move the geometry"
    );

    let mut p = shipped();
    p.fri_fold_log = 1;
    assert_ne!(
        Layout::of(&p).id(),
        id,
        "a radix change must move the geometry"
    );

    let m = base.manifest();
    assert_eq!(m.total_len, SHIPPED_LEN);
    assert_eq!(m.fri_layers.len(), 6);
    assert_eq!(
        m.fri_layers[0].base, 4,
        "the first layer follows the layer count"
    );
    assert_eq!(m.fri_layers[0].depth, 27);
    assert_eq!(
        m.fri_layers[0].count, 4,
        "radix four puts four values under a leaf"
    );
    let last = m.fri_layers[5];
    assert_eq!(
        last.base + last.stride,
        base.fri.stride,
        "the layers fill the query"
    );
    assert_eq!(
        m.params_id,
        shipped().id(),
        "the two identities travel together"
    );
}

/// Both identities for the shipped point, pinned.
///
/// The parameter identity says which configuration; the layout identity says
/// which byte geometry that configuration implies. A verifier generator emits
/// the second alongside its constants, and the Yul hashes the constants it
/// actually compiled in, so a build where the two implementations disagree
/// fails before a proof is read.
///
/// If either of these moves, the geometry moved. That is either intended, in
/// which case update the value and the generated Solidity in the same commit,
/// or it is the bug this test exists to catch.
// The pins are the v1 launch identities; the format 7 ones are in spec/transfer/MANIFEST.md
// and checked by the transfer emitter.
#[cfg(not(feature = "fri8"))]
#[test]
fn both_identities_are_pinned_for_the_shipped_point() {
    let p = shipped();
    let l = Layout::of(&p);
    let hex = |b: &[u8; 32]| {
        let mut s = alloc::string::String::with_capacity(64);
        for x in b {
            s.push_str(&alloc::format!("{x:02x}"));
        }
        s
    };
    assert_eq!(
        hex(&p.id()),
        "4955a503dd2cd06db99f39cbdaee1dcc72d95f34c90530baa9b368c9f7653e06",
        "the parameter identity moved"
    );
    assert_eq!(
        hex(&l.id()),
        "ffeee6f482c00fa1a1e4d49f3412c7c4ec387440510b2a82e35f07b210744ed7",
        "the layout identity moved; regenerate ProofLayout.sol in the same commit"
    );
}

/// Radix two at this degree bound gives thirteen FRI layers. A fixed table of
/// twelve layer names did not survive that, and the mutation test above found
/// it by flipping the fold radix. The geometry has to be nameable at every
/// radix the parameter set admits, not just the one we ship.
#[test]
fn a_radix_two_layout_is_still_nameable() {
    let mut p = shipped();
    p.fri_fold_log = 1;
    let l = Layout::of(&p);
    assert_eq!(l.fri_layers, 13, "21 halvings, stop 8, one halving a layer");
    let w = l.words();
    assert_eq!(
        w.len(),
        19 + 4 * 13,
        "nineteen fixed words plus four a layer"
    );
    assert_eq!(w[19].0, "FRI_L0_BASE");
    assert_eq!(w[w.len() - 1].0, "FRI_L12_COUNT");
    assert_eq!(l.fri_depth(12), 29 - 13, "depth is LN - fold*(m+1)");
    assert_ne!(l.id(), Layout::of(&shipped()).id());
}
