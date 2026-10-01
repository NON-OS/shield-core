// NONOS Operating System (AGPL-3.0-or-later)

//! The `Publics` region and its shape: width one, each row a public word pinned to its value
//! by a boundary constraint, no transition. The whole region is boundary, because a public
//! word is a fact about a specific cell, not a rule relating rows.

use super::super::spec::{Air, AirExt};
use super::super::super::field::{Fp, Fp2};
use alloc::vec;
use alloc::vec::Vec;

/// One public word per row, pinned by a boundary. A caller copy constrains each
/// row to wherever the circuit computes that word, which is what makes the
/// binding positive: the word is tied to its computed cell, not merely
/// constrained to something.
#[derive(Clone)]
pub struct Publics {
    pub log_t: u32,
    pub words: Vec<Fp>,
}

impl Air for Publics {
    fn log_trace_len(&self) -> u32 {
        self.log_t
    }

    fn trace_width(&self) -> usize {
        1
    }

    fn window_size(&self) -> usize {
        2
    }

    fn constraint_degree(&self) -> usize {
        1
    }

    fn num_transition(&self) -> usize {
        0
    }

    fn transition(&self, _w: &[Fp], _p: &[Fp]) -> Vec<Fp> {
        vec![]
    }

    fn boundary(&self) -> Vec<(usize, usize, Fp)> {
        self.words.iter().enumerate().map(|(r, v)| (0, r, *v)).collect()
    }
}

impl AirExt for Publics {
    fn transition_ext(&self, _w: &[Fp2], _p: &[Fp2]) -> Vec<Fp2> {
        vec![]
    }
}

impl Publics {
    /// No transition constraints: publics bind by boundary and wiring. The
    /// generic form says so over any field, for the recursive verifier.
    pub fn transition_gen<F: crate::field::Felt>(&self, _w: &[F], _p: &[F]) -> Vec<F> {
        Vec::new()
    }


    pub fn trace(&self) -> Vec<Fp> {
        let n = 1usize << self.log_t;
        let mut t = vec![Fp::ZERO; n];
        t[..self.words.len()].copy_from_slice(&self.words);
        t
    }
}
