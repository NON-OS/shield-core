// NONOS Operating System (AGPL-3.0-or-later)

//! The compose gadget itself: what it holds, how it is built, and where each
//! of its cells sits.
//!
//! Where `ComposeCheck` hand-arithmetizes the join-split's three transitions,
//! this recomputes *any* inner AIR's transition from the out-of-domain frame by
//! evaluating the inner AIR's own constraint code at `Ext2<F>`, the inner
//! extension carried as base-field pairs. It reproduces `compose_ext` element
//! for element: the vanishing tower and factor `E = (z - g^(t-1)) * (z^t -
//! 1)^-1`, the `num_transition` recomputed transition values, the boundary
//! quotients, and their batched sum against the claimed `comp_z`. Every count
//! is read from the inner AIR, so the same gadget serves a 3-constraint
//! join-split or a 62-constraint step AIR. Window size two only, matching every
//! money-grade inner in use; a wider window would need the exempt product built
//! incrementally.

use super::super::super::field::{Fp, Fp2};
use super::super::compose_check::ComposeBoundary;
use super::super::compose_strip::OutStatement;
use super::super::spec::{Air, AirExt};
use super::generic::GenericTransition;
use super::slots::Slots;
use alloc::vec::Vec;

pub struct ComposeCheckGen<A> {
    pub(super) air: A,
    pub(super) frame: Vec<Fp2>,
    pub(super) periodic: Vec<Fp2>,
    /// The inner's drawn challenges, lifted. Empty for an inner whose copy
    /// constraint is argued at circuit constants.
    pub(super) chal: Vec<Fp2>,
    pub(super) coeffs: Vec<Fp2>,
    pub(super) z: Fp2,
    pub(super) comp_z: Fp2,
    pub(super) g_tm1: Fp,
    pub(super) t: u64,
    pub(super) boundaries: Vec<ComposeBoundary>,
    pub(super) slots: Slots,
    /// Strip mode: the statement side of each base output, evaluated here
    /// over the frame and periodic cells; the product side arrives in the
    /// acc slots from the strip region.
    pub(super) strip_stmt: Option<Vec<OutStatement>>,
    /// For each boundary, the public word it pins, if it pins one. Those
    /// quotients read the word from its slot, so the statement enters as a
    /// cell the assembly binds and not as a constant of this region.
    pub(super) public_of: Vec<Option<usize>>,
    pub(super) public_words: Vec<Fp>,
}

impl<A: AirExt + GenericTransition> ComposeCheckGen<A> {
    /// Build the witness-form check from the inner AIR, its out-of-domain frame,
    /// the periodic values and batching coefficients at `z`, the point, the claimed
    /// composition, and the inner trace-domain generator `g`. The public statement
    /// rides the trace and is bound by the assembly, so the AIR is
    /// instance-independent.
    #[allow(clippy::too_many_arguments)]
    pub fn new_witness(
        air: A,
        frame: Vec<Fp2>,
        periodic: Vec<Fp2>,
        coeffs: Vec<Fp2>,
        z: Fp2,
        comp_z: Fp2,
        g: Fp,
    ) -> ComposeCheckGen<A> {
        assert_eq!(air.window_size(), 2, "compose gadget supports window size two");
        let log_t = air.log_trace_len();
        let t = 1u64 << log_t;
        let chal: Vec<Fp2> = air.challenges_gen().into_iter().map(Fp2::from_base).collect();
        let slots = Slots {
            w: air.window_size() * air.trace_width(),
            p: air.periodic_columns().len(),
            ch: chal.len(),
            nt: air.num_transition(),
            b: air.boundary().len(),
            k: log_t as usize,
            strip: false,
            pw: 0,
        };
        let boundaries = air
            .boundary()
            .iter()
            .map(|(col, row, e)| ComposeBoundary {
                col: *col,
                g_row: g.pow(*row as u64),
                expected: *e,
            })
            .collect();
        ComposeCheckGen {
            air,
            frame,
            periodic,
            chal,
            coeffs,
            z,
            comp_z,
            g_tm1: g.pow(t - 1),
            t,
            boundaries,
            slots,
            strip_stmt: None,
            public_of: Vec::new(),
            public_words: Vec::new(),
        }
    }

    /// The strip form: same slots plus one acc cell per transition, the
    /// recompute constraints replaced by pins `out = acc + statement`, the
    /// statement evaluated over this region's own input cells. Base input lane
    /// u of the recording is window column u here, by the shared ordering of
    /// frame, then periodic, then challenge pairs.
    pub fn into_strip(mut self, stmt: Vec<OutStatement>) -> Self {
        assert_eq!(stmt.len(), 2 * self.slots.nt, "one statement per base output");
        self.slots.strip = true;
        self.strip_stmt = Some(stmt);
        self
    }

    /// Read the inner's public words from cells rather than constants.
    ///
    /// The inner pins its public words in a publics region, word `k` at one
    /// column and row `r0 + k`, each by a boundary whose value is the word. As
    /// constants those values are the statement, and a region that carries them
    /// is a region of one spend: its program, and so the outer's periodic
    /// columns, change with every payment. Here each such boundary reads its
    /// word from slot `pubw(k)` instead, and the assembly binds that slot to the
    /// cell the transcript absorbed the word from.
    ///
    /// The run is found by position, the unique `r0` where `words[k]` is pinned
    /// at `(col, r0 + k)` for every `k`, never by value: words repeat (a zero
    /// fee beside a zero recipient), and a match by value could bind a quotient
    /// to the wrong word. No run, or more than one, is refused.
    pub fn with_public_words(mut self, words: &[Fp]) -> Self {
        let bs: Vec<(usize, usize, Fp)> = self.air.boundary();
        let starts: Vec<(usize, usize)> = bs
            .iter()
            .filter(|(_, _, v)| words.first() == Some(v))
            .map(|(c, r, _)| (*c, *r))
            .filter(|&(c, r0)| {
                words.iter().enumerate().all(|(k, w)| bs.iter().any(|&(bc, br, bv)| bc == c && br == r0 + k && bv == *w))
            })
            .collect();
        let mut distinct = starts.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert!(distinct.len() == 1, "the public words are pinned as one run, found {}", distinct.len());
        let (col, r0) = distinct[0];
        self.public_of = bs
            .iter()
            .map(|&(c, r, _)| (c == col && r >= r0 && r < r0 + words.len()).then(|| r - r0))
            .collect();
        self.public_words = words.to_vec();
        self.slots.pw = words.len();
        self
    }

    /// The base column of public word `k`'s value.
    pub fn public_col(&self, k: usize) -> usize {
        2 * self.slots.pubw(k)
    }

    /// How many public words this region reads from cells.
    pub fn n_public(&self) -> usize {
        self.slots.pw
    }

    /// The base column of acc cell `i`, for the strip binding.
    pub fn acc_col(&self, i: usize) -> usize {
        2 * self.slots.acc(i)
    }

    // The cell-column accessors: this region is the single source of truth for
    // its own slot layout, so a recursive assembly binds its frame, periodic,
    // challenge, point, coefficient, and composition cells to their sources
    // without duplicating the slot formula (which would drift from `trace`).
    // Each returns the base column of the `c0` lane; the `c1` lane is the next
    // column.

    /// The base column of frame value `i`.
    pub fn frame_col(&self, i: usize) -> usize {
        2 * self.slots.frame(i)
    }
    /// The base column of periodic value `j` at the point.
    pub fn periodic_col(&self, j: usize) -> usize {
        2 * self.slots.periodic(j)
    }
    /// The base column of challenge `i`, beta then gamma.
    pub fn chal_col(&self, i: usize) -> usize {
        2 * self.slots.chal(i)
    }
    /// How many challenges the inner's transition takes.
    pub fn n_chal(&self) -> usize {
        self.slots.ch
    }
    /// The base column of the out-of-domain point `z`.
    pub fn z_col(&self) -> usize {
        2 * self.slots.z()
    }
    /// The base column of batching coefficient `i`.
    pub fn coeff_col(&self, i: usize) -> usize {
        2 * self.slots.coeff(i)
    }
    /// The base column of the claimed composition value.
    pub fn comp_z_col(&self) -> usize {
        2 * self.slots.comp_z()
    }
    /// The frame length, so a binding loop sizes to the inner AIR.
    pub fn frame_len(&self) -> usize {
        self.slots.w
    }
    /// The batching-coefficient count (transitions plus boundaries).
    pub fn num_coeff(&self) -> usize {
        self.slots.nt + self.slots.b
    }
}

impl<A: AirExt + GenericTransition> AirExt for ComposeCheckGen<A> {
    fn transition_ext(&self, window: &[Fp2], periodic: &[Fp2]) -> Vec<Fp2> {
        self.transition_impl(window, periodic)
    }
}

impl<A: AirExt + GenericTransition> Air for ComposeCheckGen<A> {
    fn log_trace_len(&self) -> u32 {
        1
    }

    fn trace_width(&self) -> usize {
        2 * self.slots.total()
    }

    fn window_size(&self) -> usize {
        2
    }

    fn constraint_degree(&self) -> usize {
        // The recompute constraint carries the inner transition's degree in
        // the frame variables; the comp_z batching is degree three. In strip
        // mode the recompute is elsewhere and the pins are linear.
        if self.strip_stmt.is_some() {
            3
        } else {
            self.air.constraint_degree().max(3)
        }
    }

    fn num_transition(&self) -> usize {
        2 * self.slots.num_constraints()
    }

    fn transition(&self, window: &[Fp], periodic: &[Fp]) -> Vec<Fp> {
        self.transition_impl(window, periodic)
    }

    fn boundary(&self) -> Vec<(usize, usize, Fp)> {
        // Witness form: nothing pinned; the assembly binds the statement cells to
        // their sources (frame to the DEEP claims, coefficients and point to the
        // transcript, challenges to its squeezes, comp_z to the DEEP check).
        Vec::new()
    }
}
