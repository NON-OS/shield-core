// NONOS Operating System (AGPL-3.0-or-later)

//! The money-grade DEEP STARK proof: the trace stays in the base field, but the
//! out-of-domain frame, the composition openings, and the DEEP polynomial are all
//! in the extension, because the out-of-domain point is sampled at `z in Fp2`.

use super::super::super::field::{Fp, Fp2};
use super::super::super::fri_ext::FriProofExt;
use alloc::vec::Vec;

/// One consistency query at FRI's `k`th position `p`: the whole base-field
/// trace row at `p` and the extension composition at `p`. The trace row is
/// authenticated by a single wide-leaf path and the composition by an
/// extension-leaf path. The DEEP value is not here: it is FRI's `k`th
/// layer-zero opening, read at slot `p / (n / 4)` (`fri_ext::deep_leaf`).
#[derive(Clone)]
pub struct StarkQueryExt {
    pub trace: Vec<Fp>,
    pub trace_path: Vec<[u8; 32]>,
    pub comp: Fp2,
    pub comp_path: Vec<[u8; 32]>,
}

/// A complete money-grade STARK proof. The trace is committed row-wise as one
/// wide-leaf tree, so there is a single trace root and one trace path per query.
#[derive(Clone)]
pub struct StarkProofExt {
    pub trace_root: [u8; 32],
    pub comp_root: [u8; 32],
    /// The trace columns evaluated at `g^k * z` for each window row `k`, row-major
    /// as a transition window: `ood_frame[k * width + col]`, in `Fp2`.
    pub ood_frame: Vec<Fp2>,
    pub fri: FriProofExt,
    pub queries: Vec<StarkQueryExt>,
}
