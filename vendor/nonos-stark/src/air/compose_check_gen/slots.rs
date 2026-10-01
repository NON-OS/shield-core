// NONOS Operating System (AGPL-3.0-or-later)

//! The compose gadget's trace slot layout. One slot is one `Ext2` value, two
//! base cells, and every count comes from the inner AIR, so the same layout
//! serves a three constraint join-split and a sixty two constraint step AIR.
//!
//! The order is the statement's: the inputs a binding reaches in from outside
//! (frame, periodic, challenges), then the point and the coefficients, then
//! the witnessed intermediates. Anything that moves an input's position moves
//! every published column with it, which is why the challenges sit with the
//! inputs rather than at the end where they would be cheaper to append.

/// The slot layout, all counts derived from the inner AIR.
pub struct Slots {
    /// Frame length: inner window size times trace width.
    pub w: usize,
    /// Inner periodic count.
    pub p: usize,
    /// Inner challenge count, zero unless the inner drew its own.
    pub ch: usize,
    /// Inner transition count.
    pub nt: usize,
    /// Inner boundary count.
    pub b: usize,
    /// Tower height: inner log trace length, so `z^t = z^(2^k)`.
    pub k: usize,
    /// Strip mode: the recompute leaves for the strip region, and `nt` acc
    /// slots arrive for its final accumulators, bound in by cycle.
    pub strip: bool,
    /// Public words the boundary quotients read from cells rather than from the
    /// inner AIR's constants. Zero leaves the layout exactly as it was; the
    /// slots sit after every other one, so no existing column moves.
    pub pw: usize,
}

impl Slots {
    pub fn frame(&self, i: usize) -> usize {
        i
    }
    pub fn periodic(&self, i: usize) -> usize {
        self.w + i
    }
    /// Challenge `i`, beta then gamma. Sits with the other inputs so the base
    /// lane a recorded statement names is still this region's own column.
    pub fn chal(&self, i: usize) -> usize {
        self.w + self.p + i
    }
    /// One past the inputs, which is where the recording's lane numbering ends.
    pub fn n_inputs(&self) -> usize {
        self.w + self.p + self.ch
    }
    pub fn z(&self) -> usize {
        self.n_inputs()
    }
    pub fn coeff(&self, i: usize) -> usize {
        self.z() + 1 + i
    }
    pub fn z_h_inv(&self) -> usize {
        self.z() + 1 + self.nt + self.b
    }
    pub fn e(&self) -> usize {
        self.z_h_inv() + 1
    }
    pub fn out(&self, i: usize) -> usize {
        self.e() + 1 + i
    }
    pub fn comp_z(&self) -> usize {
        self.out(self.nt)
    }
    pub fn quot(&self, j: usize) -> usize {
        self.comp_z() + 1 + j
    }
    pub fn tower(&self, k: usize) -> usize {
        self.quot(self.b) + k
    }
    pub fn acc(&self, i: usize) -> usize {
        self.tower(self.k) + i
    }
    /// Public word `i`: its low lane is the value, its high lane is unread.
    pub fn pubw(&self, i: usize) -> usize {
        self.tower(self.k) + if self.strip { self.nt } else { 0 } + i
    }
    pub fn total(&self) -> usize {
        self.pubw(self.pw)
    }
    /// Ext2 transition constraints: tower + z_h_inv + E + out + boundary + comp_z.
    pub fn num_constraints(&self) -> usize {
        self.k + 1 + 1 + self.nt + self.b + 1
    }
}
