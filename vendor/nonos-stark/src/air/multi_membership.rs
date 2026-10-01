// NONOS Operating System (AGPL-3.0-or-later)

//! Verify several Poseidon Merkle openings in one STARK, the heavy half of a FRI
//! query verifier: a query opens two values per layer, all under different
//! roots, and this proves the whole batch at once. Each opening occupies a fixed
//! run of rows and is a Merkle path verification; at an opening boundary the
//! state resets to the next opening's public leaf and first sibling. The leaves
//! are public (a FRI proof reveals its openings), and every root is pinned at
//! its checkpoint.

use super::super::field::Fp;
use super::poseidon::{Poseidon, RATE, WIDTH};
use alloc::vec::Vec;

/// One opening: a public leaf digest, its committed root, and the sibling path.
#[derive(Clone)]
pub struct Opening {
    pub leaf: [Fp; RATE],
    pub root: [Fp; RATE],
    pub siblings: Vec<[Fp; RATE]>,
    pub directions: Vec<bool>,
}

#[derive(Clone)]
pub struct MultiMembership {
    hasher: Poseidon,
    log_rounds: u32,
    depth: usize,
    openings: Vec<Opening>,
    witness_path: bool,
    /// The S-box split: x2 and x4 witnessed per lane, the round constraint
    /// falling from degree 8 to 4. Opt-in, appended columns, so the default
    /// forms and everything built on their coordinates stay byte-identical.
    split: bool,
    /// Pin the bottom index bit. The path direction of the bottom level lives only
    /// in which half of the initial state the leaf occupies, so a scalar that
    /// hashes the position (a nullifier over a leaf index) is otherwise free to
    /// disagree with it in that one bit and retire the note under the sibling
    /// position. This witnesses the bottom direction as a bit and a canonical leaf
    /// it selects from the two halves, so the assembly can bind the bit to the
    /// recovered scalar. Opt-in, appended columns, so the default forms and the
    /// coordinates built on them stay byte-identical.
    pin0: bool,
    /// Pin the half of a pair leaf the quotient reads.
    ///
    /// A FRI layer that shares a leaf between a value and its fold partner
    /// commits `[a.c0, a.c1, b.c0, b.c1]`, and which of the two the quotient
    /// reads is decided by the consistency index's top bit. The assembly wires
    /// a fixed lane of that leaf into the quotient, so without this the prover
    /// chooses which committed value feeds it, which is not a choice a prover
    /// may have.
    ///
    /// Witnesses the top bit and the selected extension value; the assembly
    /// binds the bit to the same index scalar every other opening is bound to.
    /// Same shape as `pin0` one level down: there the bit selects a half of the
    /// state, here a half of the leaf. Opt-in, appended after `pin0`'s columns.
    /// THREAT 6a.
    pin_half: bool,
    /// Per opening: `None` binds the whole leaf, `Some(bit)` binds the half the
    /// bit names. Empty unless `pin_half`.
    ///
    /// Not every opening in a set wants the same thing. A FRI layer's leaf holds
    /// a value and its fold partner and the fold reads both, so binding the pair
    /// is what that opening wants and a selector there would throw half of it
    /// away. A consistency opening reads one value at one position out of the
    /// same shape of leaf, and that one needs the bit.
    halves: Vec<Option<bool>>,
    /// Cells the production form pins to constants, as `(col, row, value)` in
    /// the region's own coordinates.
    ///
    /// The production form pins nothing, which is right for a path: every word
    /// it absorbs is either bound by the assembly or is a sibling the prover is
    /// entitled to choose. It is wrong for a chain that absorbs a domain
    /// constant, because that word is a witness cell like any other and a
    /// prover who moves it derives a different key down a chain that still
    /// closes. Opt-in, no column added, so every coordinate built on the
    /// default forms is untouched.
    bound: Vec<(usize, usize, Fp)>,
}

impl MultiMembership {
    /// Build the AIR for a batch of equal-depth openings under `hasher`. The
    /// siblings, directions, and the roots ride the periodic columns and boundaries:
    /// instance-specific structure, fine for a per-proof AIR.
    pub fn new(hasher: Poseidon, log_rounds: u32, openings: Vec<Opening>) -> MultiMembership {
        let depth = openings.first().map(|o| o.siblings.len()).unwrap_or(0);
        MultiMembership {
            hasher,
            log_rounds,
            depth,
            openings,
            witness_path: false,
            split: false,
            pin0: false,
            pin_half: false,
            halves: Vec::new(),
            bound: Vec::new(),
        }
    }

    /// The production form: the sibling and direction of each compression ride the
    /// trace (a boolean-constrained direction plus RATE sibling columns), so the AIR
    /// is instance-independent (round constants, the slot and opening selectors, and
    /// the reset column are the only periodic columns; no boundary is pinned). The
    /// opened leaf is bound by the assembly grand product to where the fold consumes
    /// it, and the root at the checkpoint is bound to the transcript-absorbed root,
    /// so the path authenticates the fold value against the committed root.
    pub fn new_witness(
        hasher: Poseidon,
        log_rounds: u32,
        openings: Vec<Opening>,
    ) -> MultiMembership {
        let depth = openings.first().map(|o| o.siblings.len()).unwrap_or(0);
        MultiMembership {
            hasher,
            log_rounds,
            depth,
            openings,
            witness_path: true,
            split: false,
            pin0: false,
            pin_half: false,
            halves: Vec::new(),
            bound: Vec::new(),
        }
    }

    /// The production form with the S-box split: two witnessed squares per
    /// lane after the sibling columns, ceiling 4 instead of 8. Everything
    /// else is `new_witness` to the cell.
    pub fn new_witness_split(
        hasher: Poseidon,
        log_rounds: u32,
        openings: Vec<Opening>,
    ) -> MultiMembership {
        let depth = openings.first().map(|o| o.siblings.len()).unwrap_or(0);
        MultiMembership {
            hasher,
            log_rounds,
            depth,
            openings,
            witness_path: true,
            split: true,
            pin0: false,
            pin_half: false,
            halves: Vec::new(),
            bound: Vec::new(),
        }
    }

    /// The production form with the bottom index bit pinned: a witnessed bottom
    /// direction and a canonical leaf selected from the two halves, appended after
    /// the sibling columns. Everything else is `new_witness` to the cell. The
    /// assembly binds the bit column to the recovered index scalar's low bit, and
    /// the fold to the canonical leaf, so the position a nullifier hashes cannot
    /// disagree with the one the path authenticated in its bottom bit.
    pub fn new_witness_pin0(
        hasher: Poseidon,
        log_rounds: u32,
        openings: Vec<Opening>,
    ) -> MultiMembership {
        let depth = openings.first().map(|o| o.siblings.len()).unwrap_or(0);
        MultiMembership {
            hasher,
            log_rounds,
            depth,
            openings,
            witness_path: true,
            split: false,
            pin0: true,
            pin_half: false,
            halves: Vec::new(),
            bound: Vec::new(),
        }
    }

    /// The production form with named cells pinned to constants, `(col, row,
    /// value)` in this region's coordinates. Everything else is `new_witness`
    /// to the cell.
    ///
    /// For a chain whose absorbed words are domain constants rather than
    /// siblings a prover may choose. Leaving one free is a second key, a second
    /// chain, and a second nullifier over one note.
    pub fn new_witness_bound(
        hasher: Poseidon,
        log_rounds: u32,
        openings: Vec<Opening>,
        bound: Vec<(usize, usize, Fp)>,
    ) -> MultiMembership {
        let depth = openings.first().map(|o| o.siblings.len()).unwrap_or(0);
        MultiMembership {
            hasher,
            log_rounds,
            depth,
            openings,
            witness_path: true,
            split: false,
            pin0: false,
            pin_half: false,
            halves: Vec::new(),
            bound,
        }
    }

    /// The production form with both the bottom bit and the leaf's half pinned.
    ///
    /// This is the shape a recursion needs over a FRI whose layers share a leaf
    /// between a value and its fold partner: `pin0` fixes which half of the
    /// state the leaf sits in, and `pin_half` fixes which half of that leaf the
    /// quotient reads. Everything else is `new_witness` to the cell.
    /// `halves[o]` says what opening `o` binds: `None` the whole leaf, `Some(b)`
    /// the low pair when `b` is false and the high pair when it is true.
    ///
    /// It is a parameter because it is not in the opening. `directions` is the
    /// leaf's position inside the tree, and this bit distinguishes `p` from
    /// `p + half`, which is the bit above that position and is not on the path
    /// at all. Reading it off `directions` would take the top bit of the wrong
    /// number and be right only when the two happened to agree.
    pub fn new_witness_pin0_half(
        hasher: Poseidon,
        log_rounds: u32,
        openings: Vec<Opening>,
        halves: Vec<Option<bool>>,
    ) -> MultiMembership {
        assert_eq!(
            halves.len(),
            openings.len(),
            "one half selector per opening, or the quotient reads a lane nobody named"
        );
        let depth = openings.first().map(|o| o.siblings.len()).unwrap_or(0);
        MultiMembership {
            hasher,
            log_rounds,
            depth,
            openings,
            witness_path: true,
            split: false,
            pin0: true,
            pin_half: true,
            halves,
            bound: Vec::new(),
        }
    }

    /// The production form with the S-box split, whichever pins it carries:
    /// the two witnessed squares per lane sit after the sibling columns and
    /// the pinned columns move past them, every one addressed by name.
    pub fn with_split(mut self) -> MultiMembership {
        assert!(self.witness_path, "the split is a production form option");
        self.split = true;
        self
    }

    /// The column carrying the witnessed bottom direction, when pinned. Appended
    /// after the state, direction, sibling and, when split, square columns.
    pub fn dir0_col(&self) -> usize {
        WIDTH + 1 + RATE + if self.split { 2 * WIDTH } else { 0 }
    }

    /// The first column of the canonical leaf, when pinned: the leaf the fold binds
    /// to, selected from the two initial-state halves by the bottom direction.
    pub fn leaf_col(&self) -> usize {
        self.dir0_col() + 1
    }

    /// The column carrying the index's top bit, when the leaf's half is pinned.
    /// Appended after the canonical leaf.
    pub fn half_col(&self) -> usize {
        self.leaf_col() + RATE
    }

    /// The first column of the selected extension value: the `Fp2` the quotient
    /// consumes, chosen from the leaf's two halves by the bit above. Two columns,
    /// `c0` then `c1`.
    pub fn sel_col(&self) -> usize {
        self.half_col() + 1
    }

    /// Whether the checkpoint row has its own selector and rule. Always, except
    /// under `launch_v1`, which reproduces the live launch circuit for its
    /// pinned vectors and must never build a new image.
    pub fn checkpoint_fixed(&self) -> bool {
        !cfg!(feature = "launch_v1")
    }

    /// Rounds per compression, depth, and openings: the three numbers the
    /// selector schedule is built from, for a test that holds the schedule to
    /// `Shield.Checkpoint`.
    pub fn schedule(&self) -> (usize, usize, usize) {
        (self.rounds(), self.depth, self.openings.len())
    }

    /// Which half of opening `o`'s leaf the quotient reads, and false for an
    /// opening that binds the whole leaf. The constraints still hold there: the
    /// bit is zero, so the selected pair is the low half and nothing reads it.
    pub(super) fn half_of(&self, o: usize) -> bool {
        self.halves.get(o).copied().flatten().unwrap_or(false)
    }

    /// Whether opening `o` binds a selected half rather than the whole leaf.
    fn selects(&self, o: usize) -> bool {
        self.pin_half && self.halves.get(o).copied().flatten().is_some()
    }

    /// The trace cell holding opening `o`'s witnessed top bit, for the assembly
    /// to bind to the same index scalar the bottom bit is bound to.
    pub fn half_cell(&self, o: usize) -> (usize, usize) {
        (o * self.span(), self.half_col())
    }

    /// The trace cell holding opening `o`'s witnessed bottom direction: the row it
    /// starts on, and the direction column. The assembly binds the recovered
    /// scalar's low bit here.
    pub fn dir0_cell(&self, o: usize) -> (usize, usize) {
        (o * self.span(), self.dir0_col())
    }

    /// The periodic column of the checkpoint selector, the last column of
    /// either form: after the opening-start selector in the production form,
    /// after the reset in the per-proof form.
    pub fn cp_col(&self) -> usize {
        if self.witness_path {
            WIDTH + 2 + if self.pin0 { 1 } else { 0 }
        } else {
            WIDTH + 3 + RATE + WIDTH
        }
    }

    fn rounds(&self) -> usize {
        1usize << self.log_rounds
    }

    /// Slots per opening: a compression per level plus the root checkpoint.
    /// Unpadded. This region is most of the assembly's rows, and rounding here
    /// charged 32 slots for 19 at the depth the pool runs.
    fn slots(&self) -> usize {
        self.depth + 1
    }

    /// Openings padded to a power of two.
    fn log_batch(&self) -> u32 {
        self.openings
            .len()
            .next_power_of_two()
            .max(1)
            .trailing_zeros()
    }

    /// Rows per opening.
    fn span(&self) -> usize {
        self.slots() * self.rounds()
    }

    /// Rows of real work. Padding now sits after them rather than inside every
    /// opening, so a stack can place these and leave the rest.
    fn work_rows(&self) -> usize {
        (1usize << self.log_batch()) * self.span()
    }

    fn initial_state(&self, opening: &Opening) -> [Fp; WIDTH] {
        inject(opening.leaf, opening.siblings[0], opening.directions[0])
    }

    /// The `(row, column)` of each opening's committed scalar in the trace, one
    /// per opening. A Poseidon-committed FRI leaf is `[value, 0, 0, 0]`, so the
    /// scalar is lane zero of the leaf, which the first index bit places in the
    /// low half of the initial state (column zero) or the high half (column
    /// `RATE`). A wiring engine binds these cells to where a fold consumes the
    /// opened value, so the fold runs on exactly what the opening committed.
    pub fn opened_cells(&self) -> alloc::vec::Vec<(usize, usize)> {
        let span = self.span();
        /*
         * When the bottom bit is pinned, the fold binds the canonical leaf, at a
         * fixed column, rather than whichever half the direction placed it in.
         * The select constraint ties that canonical cell back to the real half,
         * so the fold still runs on what the opening committed.
         *
         * When the leaf's half is pinned too, that canonical leaf holds two
         * extension values and the fold consumes one of them. It binds the
         * selected pair, not the leaf: binding the leaf would bind its first
         * lane, which is the low half's c0 whatever the index says, and that is
         * the fixed lane this gadget exists to remove. The gadget would compile,
         * satisfy every constraint, and do nothing.
         */
        if self.pin_half {
            /*
             * Per opening, because they do not all want the same cell. One that
             * selects a half binds the selected pair; one that does not binds
             * the canonical leaf, which is the whole pair and is what a fold
             * reads. Binding the selected pair everywhere would hand a fold one
             * of the two values it needs.
             */
            return self
                .openings
                .iter()
                .enumerate()
                .map(|(o, _)| {
                    let col = if self.selects(o) {
                        self.sel_col()
                    } else {
                        self.leaf_col()
                    };
                    (o * span, col)
                })
                .collect();
        }
        if self.pin0 {
            let col = self.leaf_col();
            return self
                .openings
                .iter()
                .enumerate()
                .map(|(o, _)| (o * span, col))
                .collect();
        }
        self.openings
            .iter()
            .enumerate()
            .map(|(o, opening)| {
                let col = if opening.directions[0] { RATE } else { 0 };
                (o * span, col)
            })
            .collect()
    }
}

mod rules;
mod trace;

use trace::inject;
