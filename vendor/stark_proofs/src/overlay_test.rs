// NONOS Operating System (AGPL-3.0-or-later)
//! The launch circuit with its periodic slots overlaid (`Stack::overlay`), a v2
//! layout: every kind's schedule shares one set of columns, as the regions
//! already share their trace columns. The stacked launch circuit is untouched.
// The v2 build overlays in the assembly itself, so there is no stacked
// circuit to compare against there.
#![cfg(not(feature = "v2"))]

use crate::crypto::stark::air::{
    domain_params_blown, share_paths, stark_prove_ext_rounds, stark_verify_ext_rounds_positions,
    stark_verify_ext_rounds_why, Air,
};
use crate::crypto::stark::field::Fp;
use crate::crypto::stark::fri::FRI_FOLD_LOG;
use crate::host::{build_parts_with, Entropy};
use crate::proof_wire::{serialize_rounds, serialize_rounds_shared, ParamSet};
use crate::recursion_assembly::inner::{hasher, hide_at};
use crate::shield::batch::assemble;
use crate::shield::join::{join_split_shape, JoinSplit};
use crate::shield::member::TREE_DEPTH;
use crate::shield_params::direct;

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../spec/wallet-vectors/transfer-eth"
);

fn read(name: &str) -> String {
    std::fs::read_to_string(format!("{DIR}/{name}")).expect("a pinned vector file")
}

fn words() -> Vec<Fp> {
    let s = read("publics.json");
    let open = s.find('[').unwrap_or(0) + 1;
    let close = s[open..].find(']').map(|i| open + i).unwrap_or(open);
    s[open..close]
        .split(',')
        .filter_map(|w| w.trim().parse().ok())
        .map(Fp::from_u64)
        .collect()
}

/// Each kind's slots, read on that kind's rows, are the same schedule in the
/// overlaid layout as in the stacked one; the overlay is narrower by the sum
/// of the kinds' slots less the widest.
#[test]
fn the_overlay_carries_every_kind_on_its_own_rows() {
    let stacked = join_split_shape(TREE_DEPTH, &words());
    let mut overlaid = join_split_shape(TREE_DEPTH, &words());
    overlaid.wired_mut().overlay_periodic();
    let (a, b) = (stacked.periodic_columns(), overlaid.periodic_columns());
    let (ka, kb) = (stacked.wired().kind_map(), overlaid.wired().kind_map());
    let n_kinds = ka.len();
    let sum: usize = ka.iter().map(|k| k.1).sum();
    let widest = ka.iter().map(|k| k.1).max().unwrap_or(0);
    println!(
        "periodic columns: stacked {}, overlaid {} ({} kinds, slots {sum} summed, {widest} widest)",
        a.len(),
        b.len(),
        n_kinds
    );
    assert_eq!(a.len() - b.len(), sum - widest);
    for k in 0..n_kinds {
        // The selector is the same column in both.
        assert_eq!(a[k], b[k], "selector {k}");
        let rows: Vec<usize> = (0..a[k].len()).filter(|&r| a[k][r] == Fp::ONE).collect();
        for j in 0..ka[k].1 {
            for &r in &rows {
                assert_eq!(
                    a[ka[k].0 + j][r],
                    b[kb[k].0 + j][r],
                    "kind {k} slot {j} row {r}"
                );
            }
        }
    }
    // The wiring's columns follow, unchanged.
    let wa = &a[n_kinds + sum..];
    let wb = &b[n_kinds + widest..];
    assert_eq!(wa, wb);
}

/// A transfer proved on the overlaid circuit verifies under it, and the bytes
/// it saves are measured, in format 5 and format 6.
#[test]
#[ignore = "release tier: proves the pinned transfer on the overlaid circuit"]
fn a_transfer_on_the_overlaid_circuit() {
    let (q, grind, extra) = (
        direct::N_QUERIES,
        direct::GRIND_BITS,
        direct::EXTRA_BLOWUP_BITS,
    );
    let hex = read("entropy.hex");
    let hex = hex.trim();
    let ent: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex"))
        .collect();
    let mut e = Entropy::new(&ent);
    let (parts, _) = {
        let mut w = |n: usize| e.words(n);
        build_parts_with(&read("request.json"), &read("seed.json"), &mut w)
            .expect("the pinned request")
    };
    let mut b = assemble(vec![parts.parts]);
    let intent = b.intents.pop().expect("one statement");
    let mut js = JoinSplit {
        wired: b.wired,
        witness: b.witness,
        intent,
    };
    js.wired.wired_mut().overlay_periodic();
    let h = hasher();
    let w = e.words(4).expect("entropy");
    let blind = hide_at(
        &h,
        &mut js,
        &[w[0], w[1], w[2], w[3]],
        q,
        1usize << FRI_FOLD_LOG,
    );
    let publics = js.intent.clone();
    let params = ParamSet::of(&js.wired, q, grind, extra);
    let n_periodic = js.wired.periodic_columns().len();
    let mut witness = js.witness;
    let (rounds, tree, _air) = stark_prove_ext_rounds(
        js.wired,
        &mut witness,
        q,
        grind,
        extra,
        &publics,
        None,
        &blind,
    )
    .expect("proves");
    let root = tree.root();

    let mut verifier = join_split_shape(TREE_DEPTH, &publics);
    verifier.wired_mut().overlay_periodic();
    let log_n = domain_params_blown(&verifier, extra).0;
    let positions =
        stark_verify_ext_rounds_positions(verifier, &rounds, q, grind, extra, &root, &publics)
            .expect("the overlaid proof verifies under the overlaid circuit");

    // The stacked launch circuit does not take it.
    let stacked = join_split_shape(TREE_DEPTH, &publics);
    assert!(
        stark_verify_ext_rounds_why(stacked, &rounds, q, grind, extra, &root, &publics).is_err()
    );

    let f5 = serialize_rounds(&rounds, &params);
    let shared = share_paths(&rounds, &positions, log_n).expect("paths share");
    let f6 = serialize_rounds_shared(&rounds, &shared, &params);
    let hexroot: String = root[..24].iter().map(|b| format!("{b:02x}")).collect();
    println!(
        "overlaid: {n_periodic} periodic columns, DEEP terms {}, format 5 {} bytes, format 6 {} bytes, periodic root {hexroot}",
        verifier_terms(n_periodic),
        f5.len(),
        f6.len()
    );
}

/// DEEP terms at the launch shape: 44 columns over a window of 2, the
/// composition, and one per periodic claim.
fn verifier_terms(n_periodic: usize) -> usize {
    44 * 2 + 1 + n_periodic
}

/// The constraint vector at row `r`, and whether the boundaries hold.
fn at_row(air: &(impl Air + Sync), witness: &[Fp], periodic: &[Vec<Fp>], r: usize) -> Vec<Fp> {
    let (w, ws) = (air.trace_width(), air.window_size());
    let mut window = Vec::with_capacity(ws * w);
    for k in 0..ws {
        window.extend_from_slice(&witness[(r + k) * w..(r + k + 1) * w]);
    }
    let per: Vec<Fp> = periodic.iter().map(|c| c[r]).collect();
    air.transition(&window, &per)
}

fn boundaries_hold(air: &impl Air, witness: &[Fp]) -> bool {
    let w = air.trace_width();
    air.boundary()
        .iter()
        .all(|&(col, row, val)| witness[row * w + col] == val)
}

/// For any trace at all, the stacked and the overlaid circuit ask the same
/// thing of every row: their constraint vectors are equal at every row, and
/// their boundaries are the same list. So the overlay cannot switch a
/// constraint off or change what it expects, at a region boundary or anywhere
/// else, whatever the witness. A random trace, not an honest one, because an
/// honest one satisfies both and would show nothing.
#[test]
fn the_overlay_asks_every_row_the_same_of_any_trace() {
    let stacked = join_split_shape(TREE_DEPTH, &words());
    let mut overlaid = join_split_shape(TREE_DEPTH, &words());
    overlaid.wired_mut().overlay_periodic();
    assert_eq!(stacked.boundary(), overlaid.boundary());
    assert_eq!(stacked.num_transition(), overlaid.num_transition());
    let (w, ws, total) = (
        stacked.trace_width(),
        stacked.window_size(),
        1usize << stacked.log_trace_len(),
    );
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    let witness: Vec<Fp> = (0..w * total)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            Fp::from_u64(x % crate::crypto::stark::field::P)
        })
        .collect();
    let (ps, po) = (stacked.periodic_columns(), overlaid.periodic_columns());
    let rows = total - (ws - 1);
    let bad = crate::crypto::stark::par::map_index(rows.div_ceil(512), |b| {
        let (lo, hi) = (b * 512, ((b + 1) * 512).min(rows));
        (lo..hi)
            .filter(|&r| at_row(&stacked, &witness, &ps, r) != at_row(&overlaid, &witness, &po, r))
            .count()
    });
    let differing: usize = bad.iter().sum();
    println!("rows compared {rows}, rows where the constraint vectors differ {differing}");
    assert_eq!(differing, 0);
}

/// The boundary tamper test: an honest witness, one cell changed alone at a
/// region's first row, its last live row or its last row, every column. The
/// overlaid circuit refuses exactly when the stacked one does, and the count of
/// refusals is printed. A tampered row only enters the windows at `r - 1` and
/// `r`, and the boundary pins, so those are what change.
#[test]
fn a_boundary_cell_changed_alone_is_refused_as_before() {
    use crate::shield::key::Break;
    use crate::shield::test::scenario::balanced_deployed;
    let stacked_js = balanced_deployed(Break::None);
    let mut overlaid_js = balanced_deployed(Break::None);
    overlaid_js.wired.wired_mut().overlay_periodic();
    let (stacked, overlaid) = (&stacked_js.wired, &overlaid_js.wired);
    let honest = &stacked_js.witness;
    assert_eq!(honest, &overlaid_js.witness);
    // Untampered, both accept: a refusal below is the tamper's, not a leftover.
    assert!(crate::witness_satisfies::satisfies(stacked, honest));
    assert!(crate::witness_satisfies::satisfies(overlaid, honest));
    let (w, ws) = (stacked.trace_width(), stacked.window_size());
    let total = 1usize << stacked.log_trace_len();
    let (ps, po) = (stacked.periodic_columns(), overlaid.periodic_columns());
    let kinds = stacked.wired().kind_map().len();

    // Every region instance's rows, from its kind's selector runs.
    let mut edges: Vec<usize> = Vec::new();
    for k in 0..kinds {
        let sel = &ps[k];
        let mut r = 0;
        while r < total {
            if sel[r] == Fp::ONE {
                let s = r;
                while r < total && sel[r] == Fp::ONE {
                    r += 1;
                }
                // first row, last live row, last row of the instance
                edges.extend([s, r - 1, r]);
            } else {
                r += 1;
            }
        }
    }
    edges.sort_unstable();
    edges.dedup();
    edges.retain(|&r| r < total);

    let refused = |air: &(dyn Fn(usize) -> Vec<Fp>), wit_ok: bool, r: usize| -> bool {
        let lo = r.saturating_sub(ws - 1);
        let hi = r.min(total - ws);
        !wit_ok || (lo..=hi).any(|row| air(row).iter().any(|v| *v != Fp::ZERO))
    };
    let (mut both, mut neither, mut differ) = (0usize, 0usize, 0usize);
    for &r in &edges {
        for c in 0..w {
            let mut t = honest.clone();
            t[r * w + c] = t[r * w + c] + Fp::ONE;
            let s_ok = boundaries_hold(stacked, &t);
            let o_ok = boundaries_hold(overlaid, &t);
            let rs = refused(&|row| at_row(stacked, &t, &ps, row), s_ok, r);
            let ro = refused(&|row| at_row(overlaid, &t, &po, row), o_ok, r);
            match (rs, ro) {
                (true, true) => both += 1,
                (false, false) => neither += 1,
                _ => differ += 1,
            }
        }
    }
    println!(
        "boundary rows {}, cells tampered {}, refused by both {both}, unconstrained in both {neither}, verdicts that differ {differ}",
        edges.len(),
        edges.len() * w
    );
    assert_eq!(differ, 0);
}

/// The launch circuit's region instances, as `Shield.Overlay.launchRegions` states
/// them: first row, height, kind. The Lean decides these are disjoint; this holds
/// the circuit to the same list, so the two cannot drift apart.
const LEAN_REGIONS: [(usize, usize, usize); 17] = [
    (0, 8, 0),
    (8, 128, 1),
    (136, 128, 1),
    (264, 128, 1),
    (392, 128, 1),
    (520, 1056, 2),
    (1576, 1056, 2),
    (2632, 64, 3),
    (2696, 64, 3),
    (2760, 256, 4),
    (3016, 256, 4),
    (3272, 1056, 5),
    (4328, 1056, 5),
    (5384, 2, 7),
    (5386, 2, 7),
    (5388, 64, 6),
    (5452, 580, 8),
];

#[test]
fn the_launch_regions_are_the_ones_lean_decides() {
    let air = join_split_shape(TREE_DEPTH, &words());
    let cols = air.periodic_columns();
    let kinds = air.wired().kind_map().len();
    let mut found: Vec<(usize, usize, usize)> = Vec::new();
    for k in 0..kinds {
        let sel = &cols[k];
        let mut r = 0;
        while r < sel.len() {
            if sel[r] == Fp::ONE {
                let s = r;
                while r < sel.len() && sel[r] == Fp::ONE {
                    r += 1;
                }
                // The selector is on for every row but the region's last.
                found.push((s, r - s + 1, k));
            } else {
                r += 1;
            }
        }
    }
    found.sort_unstable();
    assert_eq!(found, LEAN_REGIONS.to_vec());
}
