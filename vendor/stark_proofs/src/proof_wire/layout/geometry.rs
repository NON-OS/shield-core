// NONOS Operating System (AGPL-3.0-or-later)
//! Where every byte of an artifact is, as arithmetic over the parameter set.
//!
//! One set of equations, and the serializer, the strict parser, the chain's
//! decoder and the tests all agree with it. Offsets are derived, never typed:
//! a hand written table can be coherent with itself and wrong everywhere, as
//! a non-FRI depth of `LN - 1` (it is `LN`) at a domain one too large is.
//!
//! The fix is not a corrected table. It is that `log_domain` is **derived
//! here** from the parameters that define it and cannot be supplied. Nothing
//! in this module reads a proof, which is the property that lets a decoder
//! compute an offset instead of scanning to it, and lets the equations be
//! checked against bytes they never see.

use super::super::header::ParamSet;

/// A section's geometry. `end` is the first byte after it, so the next
/// section's `base` must equal it, and the last section's `end` must be the
/// file's length. That chain is the whole specification.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Section {
    pub base: usize,
    pub stride: usize,
    pub count: usize,
    pub end: usize,
}

/// Every offset in an artifact, derived from the parameter set alone.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Layout {
    /// The parameter set this geometry belongs to, so a manifest carries
    /// which configuration it describes and the two identities travel
    /// together.
    pub params_id: [u8; 32],
    /// log2 of the evaluation domain. Every tree depth comes from this and
    /// nothing else, so an error here is an error everywhere at once.
    pub log_domain: u32,
    pub fri_layers: usize,
    pub n_final: usize,
    pub n_ood: usize,
    /// The depth of every tree that is not a FRI layer, all five of them.
    pub tree_depth: usize,
    pub digest_bytes: usize,
    pub fri_fold_log: u32,
    pub n_queries: usize,
    pub trace_width: usize,
    pub n_periodic: usize,
    /// FRI query section: the quads and their paths.
    pub fri: Section,
    /// Consistency section: the trace and composition openings.
    pub cons: Section,
    /// Sidecar: the periodic claims at z, then a row and a path per query.
    pub sidecar: Section,
    /// Permutation paths, one per query, no count prefix of its own.
    pub perm: Section,
    /// The first byte after the last section: the file's length.
    pub end: usize,
}

impl Layout {
    /// The evaluation domain a proof at this parameter set is over. The same
    /// rule as `domain_params_blown`, restated over the identity's fields so
    /// a port can reach it without the AIR: the composition needs `degree`
    /// times the trace rounded to a power of two, the engine doubles that,
    /// and the point's extra blowup raises it again.
    pub fn log_domain_of(params: &ParamSet) -> u32 {
        let t = 1u64 << params.log_trace_len;
        let degree = params.constraint_degree.max(1) as u64;
        let bound = (degree * t).next_power_of_two();
        let n = (2 * bound) << params.extra_blowup_bits;
        n.trailing_zeros()
    }

    /// Layers of folding before the final polynomial is sent, and the log of
    /// that polynomial's coefficient count. The same rule as `fri::stop`: the
    /// halvings are the domain over the FRI rate, the stop takes the last
    /// `fri_stop_log` of them, and the layers take the rest `fri_fold_log` at
    /// a time. At least one layer always remains, because a verifier that
    /// folds nothing accepts any final polynomial.
    pub fn fri_shape(params: &ParamSet) -> (usize, u32) {
        let t = 1u64 << params.log_trace_len;
        let degree = params.constraint_degree.max(1) as u64;
        let halvings = (degree * t).next_power_of_two().trailing_zeros();
        let fold = params.fri_fold_log;
        let layers = if halvings < fold {
            0
        } else {
            (halvings.saturating_sub(params.fri_stop_log) / fold).max(1) as usize
        };
        (layers, halvings - layers as u32 * fold)
    }

    /// Every offset for a proof at `params`.
    pub fn of(params: &ParamSet) -> Layout {
        let log_domain = Self::log_domain_of(params);
        let (fri_layers, final_log) = Self::fri_shape(params);
        let n_final = 1usize << final_log;
        let dg = params.digest_bytes as usize;
        let q = params.n_queries as usize;
        let w = params.trace_width as usize;
        let p = params.n_periodic as usize;
        let fold = params.fri_fold_log;
        let n_ood = w * params.window_size as usize;

        /*
         * A tree commits one leaf per evaluation point, so a domain of 2^LN
         * points is a tree of depth LN. Not LN - 1. The trace, composition,
         * sidecar and permutation trees are all this depth. The DEEP value
         * is not in the consistency section at all: the check runs at FRI's
         * positions and reads it from FRI's own layer-zero opening.
         */
        let d = log_domain as usize;

        // Head: the permutation root, the region width, the trace and
        // composition roots, the out-of-domain frame, the FRI roots, the
        // final polynomial. The DEEP root is FRI's first and is not repeated.
        let head = dg + 4 + 2 * dg + 4 + 16 * n_ood + 4 + dg * fri_layers + 4 + 16 * n_final;

        let mut layer_total = 0usize;
        for m in 0..fri_layers {
            layer_total += Self::layer_bytes_at(dg, fold, log_domain, m);
        }
        let fri_stride = 4 + layer_total;
        let fri = Section { base: head, stride: fri_stride, count: q, end: head + 4 + q * fri_stride };

        // The grind nonces sit between the FRI queries and the consistency
        // section, belonging to neither: the query grind's, one per chunk of
        // a split grind, then one per layer when the commit rounds are ground.
        let fold_nonces = if params.commit_grind_bits != 0 { fri_layers } else { 0 };
        let query_nonces = params.grind_chunks.max(1) as usize;
        let cons_base = fri.end + 8 * query_nonces + 8 * fold_nonces;
        let path = 4 + dg * d;
        let cons_stride = 4 + 8 * w + path + 16 + path;
        let cons =
            Section { base: cons_base, stride: cons_stride, count: q, end: cons_base + 4 + q * cons_stride };

        let sidecar_base = cons.end;
        let sidecar_stride = 8 * p + path;
        let sidecar = Section {
            base: sidecar_base,
            stride: sidecar_stride,
            count: q,
            end: sidecar_base + 4 + 16 * p + q * sidecar_stride,
        };

        let perm_base = sidecar.end;
        let perm = Section { base: perm_base, stride: path, count: q, end: perm_base + q * path };

        Layout {
            params_id: params.id(),
            log_domain,
            fri_layers,
            n_final,
            n_ood,
            tree_depth: d,
            digest_bytes: dg,
            fri_fold_log: fold,
            n_queries: q,
            trace_width: w,
            n_periodic: p,
            fri,
            cons,
            sidecar,
            perm,
            end: perm.end,
        }
    }

    /// The tree depth of FRI layer `m`. A radix `2^fold` layer puts `2^fold`
    /// values under one leaf, so layer zero has `2^(LN - fold)` leaves and
    /// each layer after it loses `fold` more. The `- fold` is the radix, not
    /// a constant: at radix two it is `LN - 1 - m`, at radix four
    /// `LN - 2 - 2m`. Writing the radix into the expression is the point;
    /// a table of `-2-2m` silently stops being true when the fold changes.
    fn depth_at(fold: u32, log_domain: u32, m: usize) -> usize {
        (log_domain - fold * (m as u32 + 1)) as usize
    }

    fn layer_bytes_at(digest_bytes: usize, fold: u32, log_domain: u32, m: usize) -> usize {
        let values = 1usize << fold;
        16 * values + 4 + digest_bytes * Self::depth_at(fold, log_domain, m)
    }

    /// The tree depth of FRI layer `m`.
    pub fn fri_depth(&self, m: usize) -> usize {
        Self::depth_at(self.fri_fold_log, self.log_domain, m)
    }

    /// The bytes FRI layer `m` occupies inside one query.
    pub fn layer_bytes(&self, m: usize) -> usize {
        Self::layer_bytes_at(self.digest_bytes, self.fri_fold_log, self.log_domain, m)
    }

    /// Where query `i`'s FRI data begins.
    pub fn fri_query(&self, i: usize) -> usize {
        self.fri.base + 4 + i * self.fri.stride
    }

    /// Where query `i`'s consistency opening begins.
    pub fn cons_query(&self, i: usize) -> usize {
        self.cons.base + 4 + i * self.cons.stride
    }

    /// Where query `i`'s periodic row begins.
    pub fn sidecar_query(&self, i: usize) -> usize {
        self.sidecar.base + 4 + 16 * self.n_periodic + i * self.sidecar.stride
    }

    /// Where query `i`'s permutation path begins.
    pub fn perm_query(&self, i: usize) -> usize {
        self.perm.base + i * self.perm.stride
    }

    /// Every section abuts the next and the last one ends the file.
    ///
    /// This is necessary and **not sufficient**: two wrong section sizes can
    /// compensate and still land on the last byte. What closes that hole is
    /// the byte walker, which asserts every length prefix inside the file
    /// against the value derived here rather than checking a final sum. Both
    /// layers are kept for that reason and neither replaces the other.
    pub fn chain_closes(&self, proof_len: usize) -> Result<(), &'static str> {
        if self.cons.base != self.fri.end + 8 {
            return Err("the consistency section does not follow the grind nonce");
        }
        if self.sidecar.base != self.cons.end {
            return Err("the sidecar does not follow the consistency section");
        }
        if self.perm.base != self.sidecar.end {
            return Err("the permutation paths do not follow the sidecar");
        }
        if self.end != proof_len {
            return Err("the layout does not end on the artifact's last byte");
        }
        Ok(())
    }
}
