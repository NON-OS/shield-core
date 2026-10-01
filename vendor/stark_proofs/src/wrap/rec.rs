// NONOS Operating System (AGPL-3.0-or-later)

//! A field element that remembers how it was made.
//!
//! The wrap has to evaluate the outer's constraints at z inside a circuit,
//! and the outer's constraints are Rust: twelve bodies, each one generic
//! function over any field, under a compose gadget that is one more. Laid
//! out the way the compose gadget lays them out, one row of slots, they
//! are 6,380 columns wide, which is five times what a transaction can
//! carry. Laid out as the sequence of field operations that computing them
//! actually is, they are tens of thousands of rows of a three column
//! region, and that sequence is what this type records.
//!
//! `Rec<V>` is a handle into a tape of values `V`, the base field for a
//! body evaluated the way the prover evaluates it and the extension for a
//! body evaluated at z. Every addition, multiplication, constant and
//! inversion the bodies perform on it lands on the tape as one operation
//! with the value it produced, so the same code that proves the outer emits
//! the program the wrap enforces, and nothing is transcribed by hand. A
//! comparison reads values and records nothing: the bodies are polynomials
//! and never branch on one.

use crate::crypto::stark::air::{LineOp, Program};
use crate::crypto::stark::field::{Felt, Fp, Fp2};
use core::marker::PhantomData;
use std::collections::BTreeMap;
use std::sync::Mutex;

/// One operation of the program, over handles into the same tape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// A constant of the circuit.
    Const,
    /// The `k`th input: a cell the assembly wires in.
    Input(usize),
    Add(u32, u32),
    Sub(u32, u32),
    Mul(u32, u32),
    /// The multiplicative inverse, enforced as `a * c = 1`.
    Inv(u32),
}

/// A value a tape can hold: how it is keyed for constant sharing, how it is
/// carried into a program, and which tape is its own.
pub trait Recorded: Felt + Send + 'static {
    fn key(self) -> (u64, u64);
    fn widen(self) -> Fp2;
    fn tape() -> &'static Mutex<Option<Tape<Self>>>;
}

static TAPE_FP: Mutex<Option<Tape<Fp>>> = Mutex::new(None);
static TAPE_FP2: Mutex<Option<Tape<Fp2>>> = Mutex::new(None);

impl Recorded for Fp {
    fn key(self) -> (u64, u64) {
        (self.to_u64(), 0)
    }
    fn widen(self) -> Fp2 {
        Fp2::from_base(self)
    }
    fn tape() -> &'static Mutex<Option<Tape<Fp>>> {
        &TAPE_FP
    }
}

impl Recorded for Fp2 {
    fn key(self) -> (u64, u64) {
        (self.c0.to_u64(), self.c1.to_u64())
    }
    fn widen(self) -> Fp2 {
        self
    }
    fn tape() -> &'static Mutex<Option<Tape<Fp2>>> {
        &TAPE_FP2
    }
}

/// The program and the values it produced on the inputs it was recorded on.
#[derive(Clone, Debug)]
pub struct Tape<V> {
    pub ops: Vec<Op>,
    pub vals: Vec<V>,
    consts: BTreeMap<(u64, u64), u32>,
}

impl<V: Recorded> Tape<V> {
    /// Zero and one first, so the handles `Rec::ZERO` and `Rec::ONE` are
    /// constants of every tape rather than values that have to be recorded.
    fn seeded() -> Tape<V> {
        let mut t = Tape { ops: Vec::new(), vals: Vec::new(), consts: BTreeMap::new() };
        t.push_const(V::ZERO);
        t.push_const(V::ONE);
        t
    }

    fn push(&mut self, op: Op, val: V) -> u32 {
        let id = self.ops.len() as u32;
        self.ops.push(op);
        self.vals.push(val);
        id
    }

    fn push_const(&mut self, v: V) -> u32 {
        let key = v.key();
        if let Some(id) = self.consts.get(&key) {
            return *id;
        }
        let id = self.push(Op::Const, v);
        self.consts.insert(key, id);
        id
    }

    pub fn len(&self) -> usize {
        self.ops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// How many of each: the row budget of the region that enforces this.
    pub fn counts(&self) -> (usize, usize, usize, usize, usize, usize) {
        let mut c = (0, 0, 0, 0, 0, 0);
        for op in &self.ops {
            match op {
                Op::Const => c.0 += 1,
                Op::Input(_) => c.1 += 1,
                Op::Add(..) => c.2 += 1,
                Op::Sub(..) => c.3 += 1,
                Op::Mul(..) => c.4 += 1,
                Op::Inv(_) => c.5 += 1,
            }
        }
        c
    }

    /// The tape as the program a region enforces, with the steps named as
    /// outputs pinned to zero.
    pub fn program(&self, outputs: &[u32]) -> Program {
        let ops = self
            .ops
            .iter()
            .enumerate()
            .map(|(i, op)| match *op {
                Op::Const => LineOp::Const(self.vals[i].widen()),
                Op::Input(k) => LineOp::Input(k),
                Op::Add(a, b) => LineOp::Add(a, b),
                Op::Sub(a, b) => LineOp::Sub(a, b),
                Op::Mul(a, b) => LineOp::Mul(a, b),
                Op::Inv(a) => LineOp::Inv(a),
            })
            .collect();
        Program {
            ops,
            vals: self.vals.iter().map(|v| v.widen()).collect(),
            outputs: outputs.to_vec(),
        }
    }

    /// The program run again on other inputs, by a reader that trusts the
    /// tape's constants and nothing else: what a verifier of the region does.
    pub fn replay(&self, inputs: &[V]) -> Vec<V> {
        let mut v: Vec<V> = Vec::with_capacity(self.ops.len());
        for (i, op) in self.ops.iter().enumerate() {
            let x = match *op {
                Op::Const => self.vals[i],
                Op::Input(k) => inputs[k],
                Op::Add(a, b) => v[a as usize] + v[b as usize],
                Op::Sub(a, b) => v[a as usize] - v[b as usize],
                Op::Mul(a, b) => v[a as usize] * v[b as usize],
                Op::Inv(a) => v[a as usize].inv(),
            };
            v.push(x);
        }
        v
    }
}

/// One tape per value type for the process, behind a lock: the wired engine
/// evaluates its regions across threads, and every operation from every
/// thread belongs to the same program. An operation is appended after its
/// operands exist, so the order the lock hands out is a valid evaluation
/// order whatever the interleaving.
fn with<V: Recorded, T>(f: impl FnOnce(&mut Tape<V>) -> T) -> T {
    let mut guard = V::tape().lock().unwrap_or_else(|e| e.into_inner());
    f(guard.get_or_insert_with(Tape::seeded))
}

/// A handle into the process's tape of `V`.
#[derive(Debug)]
pub struct Rec<V> {
    id: u32,
    _v: PhantomData<V>,
}

impl<V> Clone for Rec<V> {
    fn clone(&self) -> Rec<V> {
        *self
    }
}

impl<V> Copy for Rec<V> {}

impl<V: Recorded> Rec<V> {
    const fn at(id: u32) -> Rec<V> {
        Rec { id, _v: PhantomData }
    }

    /// Start a fresh tape.
    pub fn start() {
        with::<V, _>(|t| *t = Tape::seeded());
    }

    /// The tape so far, leaving a fresh one behind.
    pub fn take() -> Tape<V> {
        with::<V, _>(|t| core::mem::replace(t, Tape::seeded()))
    }

    /// Input `k` of the program, with the value it has on this run.
    pub fn input(k: usize, val: V) -> Rec<V> {
        Rec::at(with::<V, _>(|t| t.push(Op::Input(k), val)))
    }

    pub fn id(self) -> u32 {
        self.id
    }

    pub fn value(self) -> V {
        with::<V, _>(|t| t.vals[self.id as usize])
    }

    fn binary(self, rhs: Rec<V>, op: fn(u32, u32) -> Op, f: fn(V, V) -> V) -> Rec<V> {
        Rec::at(with::<V, _>(|t| {
            let v = f(t.vals[self.id as usize], t.vals[rhs.id as usize]);
            t.push(op(self.id, rhs.id), v)
        }))
    }
}

impl<V: Recorded> PartialEq for Rec<V> {
    fn eq(&self, other: &Rec<V>) -> bool {
        self.id == other.id || self.value() == other.value()
    }
}

impl<V: Recorded> core::ops::Add for Rec<V> {
    type Output = Rec<V>;
    fn add(self, rhs: Rec<V>) -> Rec<V> {
        self.binary(rhs, Op::Add, |a, b| a + b)
    }
}

impl<V: Recorded> core::ops::Sub for Rec<V> {
    type Output = Rec<V>;
    fn sub(self, rhs: Rec<V>) -> Rec<V> {
        self.binary(rhs, Op::Sub, |a, b| a - b)
    }
}

impl<V: Recorded> core::ops::Mul for Rec<V> {
    type Output = Rec<V>;
    fn mul(self, rhs: Rec<V>) -> Rec<V> {
        self.binary(rhs, Op::Mul, |a, b| a * b)
    }
}

impl<V: Recorded> Felt for Rec<V> {
    const ZERO: Rec<V> = Rec::at(0);
    const ONE: Rec<V> = Rec::at(1);

    fn from_base(x: Fp) -> Rec<V> {
        Rec::at(with::<V, _>(|t| t.push_const(V::from_base(x))))
    }

    fn pow(self, mut exp: u64) -> Rec<V> {
        let mut base = self;
        let mut acc = Rec::ONE;
        while exp != 0 {
            if exp & 1 == 1 {
                acc = acc * base;
            }
            base = base * base;
            exp >>= 1;
        }
        acc
    }

    fn inv(self) -> Rec<V> {
        Rec::at(with::<V, _>(|t| {
            let v = t.vals[self.id as usize].inv();
            t.push(Op::Inv(self.id), v)
        }))
    }
}
