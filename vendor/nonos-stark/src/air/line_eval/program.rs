// NONOS Operating System (AGPL-3.0-or-later)

//! A straight-line program over the quadratic extension: what a recorded
//! evaluation is once the recorder is gone.

use super::super::super::field::Fp2;
use alloc::vec::Vec;

/// One step. Operands name earlier steps by index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineOp {
    /// A constant of the circuit, carried in the periodic columns.
    Const(Fp2),
    /// The `k`th input of the program: a cell the assembly wires in.
    Input(usize),
    Add(u32, u32),
    Sub(u32, u32),
    Mul(u32, u32),
    /// `a * c = 1`, so a zero operand has no honest row.
    Inv(u32),
}

/// The steps, the values each produced on the run the trace is built from,
/// and which steps are outputs the region pins to zero.
#[derive(Clone, Debug, Default)]
pub struct Program {
    pub ops: Vec<LineOp>,
    pub vals: Vec<Fp2>,
    pub outputs: Vec<u32>,
}

impl Program {
    /// The program run on other inputs, trusting its constants alone.
    pub fn eval(&self, inputs: &[Fp2]) -> Vec<Fp2> {
        let mut v: Vec<Fp2> = Vec::with_capacity(self.ops.len());
        for op in &self.ops {
            let x = match *op {
                LineOp::Const(k) => k,
                LineOp::Input(k) => inputs[k],
                LineOp::Add(a, b) => v[a as usize] + v[b as usize],
                LineOp::Sub(a, b) => v[a as usize] - v[b as usize],
                LineOp::Mul(a, b) => v[a as usize] * v[b as usize],
                LineOp::Inv(a) => v[a as usize].inv(),
            };
            v.push(x);
        }
        v
    }

    pub fn n_inputs(&self) -> usize {
        self.ops.iter().filter(|o| matches!(o, LineOp::Input(_))).count()
    }
}
