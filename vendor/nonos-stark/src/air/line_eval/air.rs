// NONOS Operating System (AGPL-3.0-or-later)

//! The region that enforces a straight-line program, one step per row.
//!
//! Two operands and a result per row. Over the base field that is three
//! columns; over the quadratic extension, six, each value as two base
//! cells. Which operation a row performs is a periodic selector, and a
//! constant's value rides in two more periodic columns, so the program is a
//! constant of the circuit and the trace holds values alone. Nothing in a
//! row refers to another row: an operand is the result of the step that
//! produced it because the assembly wires the two cells, which is what
//! `classes` hands it, and an input is a cell wired from wherever the
//! assembly keeps that input. The outputs are pinned to zero by boundary,
//! which is what a satisfied constraint has to be.
//!
//! The width is three or six whatever the program is. The rows are the
//! program.

use super::super::super::field::{Felt, Fp, Fp2};
use super::super::spec::{Air, AirExt};
use super::program::{LineOp, Program};
use alloc::vec::Vec;

/// sel_mul, sel_add, sel_sub, sel_inv, sel_const, k0, k1.
pub const N_PERIODIC: usize = 7;

pub struct LineEval {
    program: Program,
    log_len: u32,
    /// Extension values (six columns) rather than base values (three).
    ext: bool,
}

impl LineEval {
    /// Over the base field: a program recorded the way the prover evaluates
    /// a body, three columns.
    pub fn new_base(program: Program) -> LineEval {
        LineEval::with(program, false)
    }

    /// Over the quadratic extension: a program recorded at z, six columns.
    pub fn new_ext(program: Program) -> LineEval {
        LineEval::with(program, true)
    }

    fn with(program: Program, ext: bool) -> LineEval {
        let n = program.ops.len().max(2);
        let log_len = n.next_power_of_two().trailing_zeros();
        LineEval { program, log_len, ext }
    }

    pub fn program(&self) -> &Program {
        &self.program
    }

    pub fn rows(&self) -> usize {
        1usize << self.log_len
    }

    pub fn is_ext(&self) -> bool {
        self.ext
    }

    /// Base columns of operand a, operand b and the result, low half.
    pub fn a_col(&self) -> usize {
        0
    }
    pub fn b_col(&self) -> usize {
        if self.ext { 2 } else { 1 }
    }
    pub fn c_col(&self) -> usize {
        if self.ext { 4 } else { 2 }
    }

    /// Which rows are inputs, in program order, with the input index each
    /// carries: the assembly wires each result cell to that input's home.
    pub fn input_rows(&self) -> Vec<(usize, usize)> {
        self.program
            .ops
            .iter()
            .enumerate()
            .filter_map(|(r, op)| match op {
                LineOp::Input(k) => Some((*k, r)),
                _ => None,
            })
            .collect()
    }

    /// Every operand cell with the result cell it must equal, grouped by the
    /// producing step: one class per value that is read at least once. Cells
    /// are (row, base column) of the low half; in the extension form the
    /// high half follows the same cycle one column over and the caller
    /// wires both.
    pub fn classes(&self) -> Vec<Vec<(usize, usize)>> {
        let n = self.program.ops.len();
        let (a, b, c) = (self.a_col(), self.b_col(), self.c_col());
        let mut readers: Vec<Vec<(usize, usize)>> = alloc::vec![Vec::new(); n];
        for (r, op) in self.program.ops.iter().enumerate() {
            match *op {
                LineOp::Add(x, y) | LineOp::Sub(x, y) | LineOp::Mul(x, y) => {
                    readers[x as usize].push((r, a));
                    readers[y as usize].push((r, b));
                }
                LineOp::Inv(x) => readers[x as usize].push((r, a)),
                LineOp::Const(_) | LineOp::Input(_) => {}
            }
        }
        readers
            .into_iter()
            .enumerate()
            .filter(|(_, rd)| !rd.is_empty())
            .map(|(i, mut rd)| {
                rd.insert(0, (i, c));
                rd
            })
            .collect()
    }

    pub fn trace(&self) -> Vec<Fp> {
        let width = self.trace_width();
        let rows = self.rows();
        let v = &self.program.vals;
        let mut tr = alloc::vec![Fp::ZERO; rows * width];
        for (r, op) in self.program.ops.iter().enumerate() {
            let (a, b) = match *op {
                LineOp::Add(x, y) | LineOp::Sub(x, y) | LineOp::Mul(x, y) => {
                    (v[x as usize], v[y as usize])
                }
                LineOp::Inv(x) => (v[x as usize], Fp2::ZERO),
                LineOp::Const(_) | LineOp::Input(_) => (Fp2::ZERO, Fp2::ZERO),
            };
            let c = v[r];
            let row = &mut tr[r * width..(r + 1) * width];
            if self.ext {
                row[0] = a.c0;
                row[1] = a.c1;
                row[2] = b.c0;
                row[3] = b.c1;
                row[4] = c.c0;
                row[5] = c.c1;
            } else {
                row[0] = a.c0;
                row[1] = b.c0;
                row[2] = c.c0;
            }
        }
        tr
    }

    pub fn transition_gen<F: Felt>(&self, window: &[F], periodic: &[F]) -> Vec<F> {
        self.transition_impl(window, periodic)
    }

    fn transition_impl<F: Felt>(&self, w: &[F], p: &[F]) -> Vec<F> {
        let (s_mul, s_add, s_sub, s_inv, s_const, k0, k1) = (p[0], p[1], p[2], p[3], p[4], p[5], p[6]);
        if !self.ext {
            let (a, b, c) = (w[0], w[1], w[2]);
            return alloc::vec![
                s_mul * (c - a * b),
                s_add * (c - (a + b)),
                s_sub * (c - (a - b)),
                s_inv * (a * c - F::ONE),
                s_const * (c - k0),
            ];
        }
        let seven = F::from_base(Fp::from_u64(7));
        let (a0, a1, b0, b1, c0, c1) = (w[0], w[1], w[2], w[3], w[4], w[5]);
        // a * b over X^2 - 7, and a * c for the inverse.
        let ab0 = a0 * b0 + seven * (a1 * b1);
        let ab1 = a0 * b1 + a1 * b0;
        let ac0 = a0 * c0 + seven * (a1 * c1);
        let ac1 = a0 * c1 + a1 * c0;
        alloc::vec![
            s_mul * (c0 - ab0),
            s_mul * (c1 - ab1),
            s_add * (c0 - (a0 + b0)),
            s_add * (c1 - (a1 + b1)),
            s_sub * (c0 - (a0 - b0)),
            s_sub * (c1 - (a1 - b1)),
            s_inv * (ac0 - F::ONE),
            s_inv * ac1,
            s_const * (c0 - k0),
            s_const * (c1 - k1),
        ]
    }
}

impl AirExt for LineEval {
    fn transition_ext(&self, window: &[Fp2], periodic: &[Fp2]) -> Vec<Fp2> {
        self.transition_impl(window, periodic)
    }
}

impl Air for LineEval {
    fn log_trace_len(&self) -> u32 {
        self.log_len
    }

    fn trace_width(&self) -> usize {
        if self.ext { 6 } else { 3 }
    }

    fn window_size(&self) -> usize {
        2
    }

    fn constraint_degree(&self) -> usize {
        3
    }

    fn num_transition(&self) -> usize {
        if self.ext { 10 } else { 5 }
    }

    fn periodic_columns(&self) -> Vec<Vec<Fp>> {
        let rows = self.rows();
        let mut cols = alloc::vec![alloc::vec![Fp::ZERO; rows]; N_PERIODIC];
        for (r, op) in self.program.ops.iter().enumerate() {
            match *op {
                LineOp::Mul(..) => cols[0][r] = Fp::ONE,
                LineOp::Add(..) => cols[1][r] = Fp::ONE,
                LineOp::Sub(..) => cols[2][r] = Fp::ONE,
                LineOp::Inv(_) => cols[3][r] = Fp::ONE,
                LineOp::Const(k) => {
                    cols[4][r] = Fp::ONE;
                    cols[5][r] = k.c0;
                    cols[6][r] = k.c1;
                }
                LineOp::Input(_) => {}
            }
        }
        cols
    }

    fn transition(&self, window: &[Fp], periodic: &[Fp]) -> Vec<Fp> {
        self.transition_impl(window, periodic)
    }

    /// Every output pinned to zero, both halves in the extension form.
    fn boundary(&self) -> Vec<(usize, usize, Fp)> {
        let c = self.c_col();
        let mut b = Vec::with_capacity(2 * self.program.outputs.len());
        for &o in &self.program.outputs {
            b.push((c, o as usize, Fp::ZERO));
            if self.ext {
                b.push((c + 1, o as usize, Fp::ZERO));
            }
        }
        b
    }
}
