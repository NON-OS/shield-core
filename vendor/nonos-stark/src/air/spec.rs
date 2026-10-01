// NONOS Operating System (AGPL-3.0-or-later)

//! The algebraic intermediate representation a STARK proves. A computation is a
//! trace of `trace_width` columns; the transition reads a sliding window of
//! consecutive rows and returns the constraint values that must vanish on every
//! trace row but the last `window_size - 1`, and boundary constraints pin a
//! chosen `(column, row)` to a public value. A single column proves a chain; a
//! wider trace proves a permutation over a multi-element state, which is what a
//! hash round is. Any type implementing this is proven by the same engine.

use super::super::field::{Fp, Fp2};
use alloc::vec::Vec;

pub trait Air {
    /// Log2 of the trace length, a power of two.
    fn log_trace_len(&self) -> u32;

    /// Rows of real work, for a region stacked into a larger trace. Defaults to
    /// the padded length. A region whose padding sits at the end reports less and
    /// lets the stack reclaim it; proving one alone still uses `log_trace_len`,
    /// since a standalone trace has to be a power of two.
    fn rows(&self) -> usize {
        1usize << self.log_trace_len()
    }

    /// Number of trace columns, the width of the state.
    fn trace_width(&self) -> usize;

    /// Number of consecutive rows the transition reads (2 reads a row and its
    /// successor).
    fn window_size(&self) -> usize;

    /// The highest polynomial degree among the transition constraints, in the
    /// trace values. Squaring is 2, a linear recurrence 1, an `x^7` S-box 7. The
    /// engine sizes the evaluation domain and the low-degree test from this.
    fn constraint_degree(&self) -> usize;

    /// Number of transition constraints (the length of `transition`).
    fn num_transition(&self) -> usize;

    /// Public per-row values, one vector of length `trace_len` per column. They
    /// are interpolated over the trace domain and the engine hands the transition
    /// their value at the current point. This is how round constants, which
    /// differ every row, enter the constraints. Default: none.
    fn periodic_columns(&self) -> Vec<Vec<Fp>> {
        Vec::new()
    }

    /// The transition constraint values. `window` is laid out row-major:
    /// `window[k * trace_width + col]` is column `col` of the k-th row in the
    /// window. `periodic` holds the periodic columns evaluated at the current
    /// point, in declaration order. Each returned value must be zero on every
    /// trace row except the final `window_size - 1`.
    fn transition(&self, window: &[Fp], periodic: &[Fp]) -> Vec<Fp>;

    /// Boundary constraints as `(column, row, value)`.
    fn boundary(&self) -> Vec<(usize, usize, Fp)>;
}

/// An AIR whose transition also evaluates over the extension field. A money-grade
/// STARK samples its out-of-domain point at `z in Fp2`, so the constraints must be
/// evaluable there. An AIR implements this by writing its transition once over the
/// `Felt` abstraction and delegating both `transition` and `transition_ext` to it,
/// which keeps the trait object-safe. Only AIRs proven by the money-grade engine
/// (`stark_prove_ext`) need it.
// `Sync` lets the prover evaluate the composition and DEEP polynomials across
// cores under the `parallel` feature; every AIR is plain data, so the bound is
// satisfied automatically and the kernel build is unaffected.
//
// `Send` is there for one reason. A recursion over the settlement outer holds
// each of the outer's regions twice: boxed, for the engine that proves it, and
// typed, for the layer above that recomputes it over the tower. Those are two
// handles on one allocation, and a shared handle is only `Sync` when what it
// points at may cross a thread. Every AIR already could; this writes it down.
pub trait AirExt: Air + Send + Sync {
    /// The transition constraints over the extension field, layout as `transition`.
    fn transition_ext(&self, window: &[Fp2], periodic: &[Fp2]) -> Vec<Fp2>;

    /// Base-field lanes per copy-constraint challenge: one when beta and gamma
    /// are drawn in `Fp`, two when they are drawn in `Fp2`. Every transcript
    /// replay draws them this way.
    fn challenge_lanes(&self) -> usize {
        1
    }

    /// The two mask columns, when the AIR has them on the launch transcript:
    /// the pair opened at the out-of-domain point as one F_p^2 value
    /// (`replay_pre::mask_pair_frame`). `None` everywhere else.
    fn mask_pair(&self) -> Option<(usize, usize)> {
        None
    }

    /// How many periodic columns the AIR declares. An AIR that carries the
    /// count and not the columns, such as one read from a program image,
    /// overrides this together with `periodic_at`.
    fn periodic_count(&self) -> usize {
        self.periodic_columns().len()
    }

    /// The periodic columns at `z`, for a verifier that checks the proof's
    /// claims against them as well as against the pinned periodic tree.
    ///
    /// `None` for an AIR that carries no columns. Its claims are then bound by
    /// the DEEP check alone: every query opens each column against the pinned
    /// periodic root and folds `(P(x) - P(z)) / (x - z)` into the combination
    /// FRI tests, so a wrong claim at `z` leaves that combination far from
    /// low degree. That is the argument the on-chain verifier rests on, which
    /// never has the columns either.
    fn periodic_at(&self, g: Fp, t: usize, z: Fp2) -> Option<Vec<Fp2>> {
        Some(super::super::poly::eval_cols_on_subgroup_ext(
            g,
            t,
            &self.periodic_columns(),
            z,
        ))
    }
}

/// A shared region is the region. Every method forwards, so an engine stacking
/// a shared handle proves exactly what one stacking the value proves, and the
/// typed list that shares the allocation can be consulted beside it.
impl<T: Air + ?Sized> Air for alloc::sync::Arc<T> {
    fn log_trace_len(&self) -> u32 {
        (**self).log_trace_len()
    }
    fn rows(&self) -> usize {
        (**self).rows()
    }
    fn trace_width(&self) -> usize {
        (**self).trace_width()
    }
    fn window_size(&self) -> usize {
        (**self).window_size()
    }
    fn constraint_degree(&self) -> usize {
        (**self).constraint_degree()
    }
    fn num_transition(&self) -> usize {
        (**self).num_transition()
    }
    fn periodic_columns(&self) -> Vec<Vec<Fp>> {
        (**self).periodic_columns()
    }
    fn transition(&self, window: &[Fp], periodic: &[Fp]) -> Vec<Fp> {
        (**self).transition(window, periodic)
    }
    fn boundary(&self) -> Vec<(usize, usize, Fp)> {
        (**self).boundary()
    }
}

impl<T: AirExt + ?Sized> AirExt for alloc::sync::Arc<T> {
    fn transition_ext(&self, window: &[Fp2], periodic: &[Fp2]) -> Vec<Fp2> {
        (**self).transition_ext(window, periodic)
    }
    fn periodic_count(&self) -> usize {
        (**self).periodic_count()
    }
    fn periodic_at(&self, g: Fp, t: usize, z: Fp2) -> Option<Vec<Fp2>> {
        (**self).periodic_at(g, t, z)
    }
}
