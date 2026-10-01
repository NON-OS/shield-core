// NONOS Operating System (AGPL-3.0-or-later)

//! The public-input region: one committed word per row, each pinned by a boundary. It is the
//! surface where a circuit's public statement enters the trace, so an assembly copy-constrains
//! each computed word to its row here and the verifier reads the statement off the boundaries.
//! The binding is positive: a word is tied to the cell that computed it, not merely asserted
//! equal to a constant a prover could also satisfy elsewhere.

mod air;

pub use air::Publics;
