// NONOS Operating System (AGPL-3.0-or-later)
//! The pins whose values are the statement's public words.
//!
//! An assembly that binds the inner's public words appends one pin per word
//! after its constant pins. The values it was built with are the prover's
//! words; a verifier must not trust them, because a proof of one statement
//! made under a transcript seeded with another would then check against the
//! statement it proves and not the one it claims. `bind_public_pins`
//! overwrites them with the words the verifier was handed.

use super::WiredMultiExt;
use crate::air::fusion;
use crate::field::Fp;
use core::ops::Range;

impl WiredMultiExt {
    /// Declare the last `n` extra pins public. Called once by the assembly.
    pub fn mark_public_pins(&mut self, n: usize) {
        assert!(
            n <= self.extra_boundary.len(),
            "{n} public pins declared over {} extra pins",
            self.extra_boundary.len()
        );
        self.public_pins = n;
    }

    /// Declare region `r`'s boundaries the public pins: one per public word,
    /// in word order. A region's boundaries sit together in `Air::boundary`,
    /// in region order, so they are one run. For a circuit a chain verifies
    /// directly, whose statement is a region rather than pins an outer
    /// appended. Exclusive with `mark_public_pins`.
    pub fn mark_region_public(&mut self, r: usize) {
        assert!(self.public_pins == 0, "the pins are already the extra ones");
        let start: usize = self.regions[..r].iter().map(|x| x.boundary().len()).sum();
        let n = self.regions[r].boundary().len();
        self.region_pins = Some(start..start + n);
    }

    /// How many pins take their value from the publics.
    pub fn public_pins(&self) -> usize {
        match &self.region_pins {
            Some(r) => r.len(),
            None => self.public_pins,
        }
    }

    /// Where the public pins sit in `Air::boundary`, and so in the
    /// composition's boundary coefficients: after the regions' own
    /// boundaries and the constant pins, and before the product column's
    /// two, which `boundary` appends last. Pin k is boundary `start + k`.
    pub fn public_pin_range(&self) -> Range<usize> {
        if let Some(r) = &self.region_pins {
            return r.clone();
        }
        let end = fusion::base_boundary(&self.stack, &self.regions).len() + self.extra_boundary.len();
        end - self.public_pins..end
    }

    /// Set the public pins to `words`. A circuit with no public pins binds
    /// nothing and accepts any list; one with pins takes exactly one word per
    /// pin and refuses any other count.
    pub fn bind_public_pins(&mut self, words: &[Fp]) -> bool {
        /*
         * A region's pins hold the words the circuit was built from. They
         * cannot be rewritten, so a verifier handed other words refuses:
         * the check is that the two agree.
         */
        if let Some(r) = &self.region_pins {
            let b = fusion::base_boundary(&self.stack, &self.regions);
            return words.len() == r.len() && r.clone().zip(words).all(|(j, w)| b[j].2 == *w);
        }
        if self.public_pins == 0 {
            return true;
        }
        if words.len() != self.public_pins {
            return false;
        }
        let from = self.extra_boundary.len() - self.public_pins;
        for (pin, &w) in self.extra_boundary[from..].iter_mut().zip(words) {
            pin.2 = w;
        }
        true
    }
}
