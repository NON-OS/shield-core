// NONOS Operating System (AGPL-3.0-or-later)
//! The transcript cells the bindings address, gathered from the two recorders.

use super::sponge::OpCell;
use super::{fri, transcript};
use alloc::vec::Vec;

/// The transcript cells the bindings address, as the recorders handed them
/// out: an absorbed value is `(operation, lane)` in the inject columns, a
/// draw is the operation whose first lane read it.
#[derive(Clone, Default)]
pub struct TranscriptCells {
    pub publics: Vec<OpCell>,
    pub trace_root: Vec<OpCell>,
    pub perm_root: Vec<OpCell>,
    pub comp_root: Vec<OpCell>,
    pub frame: Vec<OpCell>,
    pub claims: Vec<OpCell>,
    /// The STARK transcript's squeeze of FRI's seed, and the FRI
    /// transcript's absorb of it, `c0` then `c1`.
    pub seed_op: usize,
    pub fri_seed: Vec<OpCell>,
    pub fri_root0: Vec<OpCell>,
    pub fri_beta_ops: Vec<usize>,
    pub fri_coeff_cells: Vec<OpCell>,
    pub fri_index_ops: Vec<usize>,
    /// Coefficients of the final polynomial, the Horner regions' length.
    pub n_final: usize,
}

impl TranscriptCells {
    /// The cells the two recorders handed out, gathered for the layout.
    pub fn of(ts: &transcript::StarkTranscript, ft: &fri::FriTranscript, n_final: usize) -> TranscriptCells {
        TranscriptCells {
            publics: ts.publics.clone(),
            trace_root: ts.trace_root.to_vec(),
            perm_root: ts.perm_root.map(|c| c.to_vec()).unwrap_or_default(),
            comp_root: ts.comp_root.to_vec(),
            frame: ts.frame.clone(),
            claims: ts.claims.clone(),
            seed_op: ts.seed_op,
            fri_seed: ft.seed_cells.to_vec(),
            fri_root0: ft.root0.to_vec(),
            fri_beta_ops: ft.beta_ops.clone(),
            fri_coeff_cells: ft.coeff_cells.clone(),
            fri_index_ops: ft.index_ops.clone(),
            n_final,
        }
    }
}
