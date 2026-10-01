// NONOS Operating System (AGPL-3.0-or-later)

//! Opening a query against the wide trace root. The row's values come by Horner from the
//! coefficients, and the single path's pruned chunk is rebuilt by hashing each neighbouring
//! row the same way the commit did, so the values are exactly what the dropped extension held
//! at the positions the path needs. One path per query carries the whole row, which is the
//! opening the wide commitment bought.

use super::super::super::field::{Fp, Fp2};
use super::super::super::poseidon_merkle::{pair_partner, PoseidonMerkleTree};
use super::super::periodic_poseidon::hash_periodic_row;
use super::super::poseidon::{Poseidon, RATE};
use super::super::prove_ext::Domain;
use super::super::wire::types_poseidon_ext::StarkQueryExtP;
use super::trace::{row_at, WideTrace, TREE_CUT};
use alloc::vec::Vec;

/// One opened query: the row's values by Horner from the coefficients, one
/// path whose pruned chunk is rebuilt by hashing each neighbouring row the
/// same way the commit did. The leaf binds all the columns at once.
#[allow(clippy::too_many_arguments)]
pub(crate) fn open(
    h: &Poseidon,
    d: &Domain,
    wt: &WideTrace,
    comp_d: &[Fp2],
    comp_tree: &PoseidonMerkleTree,
    deep_d: &[Fp2],
    deep_tree: &PoseidonMerkleTree,
    p: usize,
) -> StarkQueryExtP {
    let chunk = 1usize << TREE_CUT;
    let base_j = p & !(chunk - 1);
    let leaves: Vec<[Fp; RATE]> = (0..chunk)
        .map(|o| hash_periodic_row(h, &row_at(d, &wt.coeffs, base_j + o)))
        .collect();
    // Both codewords open the leaf that holds `p`, and carry the value that
    // shares it. The leaf index is `p % (n/2)`, which `pair_partner` and the
    // verifier's `pair_at` agree on.
    let partner = pair_partner(p, d.n);
    let pair_leaf = p % (d.n / 2);
    StarkQueryExtP {
        deep: deep_d[p],
        deep_sib: deep_d[partner],
        deep_path: deep_tree.open(pair_leaf),
        trace: row_at(d, &wt.coeffs, p),
        trace_path: wt.tree.open_with(h, p, &leaves),
        comp: comp_d[p],
        comp_sib: comp_d[partner],
        comp_path: comp_tree.open(pair_leaf),
    }
}

/// One half's path at `p`, for a trace committed in two rounds.
///
/// The pruned chunk is rebuilt exactly as `open` rebuilds it, from that half's
/// own coefficients, because that half's tree was committed over those rows
/// and no others.
pub(crate) fn open_half(h: &Poseidon, d: &Domain, wt: &WideTrace, p: usize) -> Vec<[Fp; RATE]> {
    let chunk = 1usize << TREE_CUT;
    let base_j = p & !(chunk - 1);
    let leaves: Vec<[Fp; RATE]> = (0..chunk)
        .map(|o| hash_periodic_row(h, &row_at(d, &wt.coeffs, base_j + o)))
        .collect();
    wt.tree.open_with(h, p, &leaves)
}
