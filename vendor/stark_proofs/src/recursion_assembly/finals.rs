// NONOS Operating System (AGPL-3.0-or-later)
//! One Horner region per query: the final polynomial the FRI transcript
//! absorbed, evaluated at the query's last point, so the fold's final value
//! is bound to the coefficients rather than pinned as one proof's number.

use super::fri::FriTranscript;
use super::inner::Inner;
use crate::crypto::stark::air::{AirExt, Horner};
use crate::crypto::stark::field::{Fp, Fp2};
use crate::crypto::stark::fri::{final_point, root_of_unity};
use alloc::vec::Vec;

pub fn horner_k<A: AirExt>(inner: &Inner<A>, ft: &FriTranscript, query: usize) -> (Horner, Vec<Fp>) {
    let fri = &inner.proof.fri;
    let n = 1usize << ft.log_n;
    let qk = ft.qs[query];
    let x: Fp2 = final_point(Fp::from_u64(7), root_of_unity(ft.log_n), qk % (n >> ft.n_folds), ft.n_folds);
    let region = Horner::new(fri.final_layer.clone(), x);
    let trace = region.trace();
    (region, trace)
}
