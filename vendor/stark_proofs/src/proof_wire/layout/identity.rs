// NONOS Operating System (AGPL-3.0-or-later)
//! The layout as a value a second implementation can be checked against.
//!
//! A verifier in Yul wants literal constants, because a literal is free and a
//! computed offset is not. A literal is safe only if it is generated: a typed
//! offset that is wrong produces confident Yul reading the wrong bytes.
//!
//! So the literals are generated from `Layout` and the generator's output
//! carries `id()`, a hash over the whole geometry. The Yul side computes the
//! same hash from the constants it actually compiled in, and a build that
//! disagrees fails before anything reads a proof. Two implementations, one
//! source, and a check that does not depend on anyone reading carefully.

use super::geometry::Layout;
use crate::crypto::stark::hash::keccak256;
use alloc::string::String;
use alloc::vec::Vec;

/// What the layout identity is a hash of. Separate from the parameter set's
/// tag because they answer different questions: `params` says which
/// configuration, this says which byte geometry that configuration implies.
/// A bug in the geometry moves this and leaves `params` alone, which is
/// exactly the failure it exists to catch.
pub const LAYOUT_DOMAIN: &[u8] = b"NOX_LAYOUT_V1";

/// One FRI layer's geometry inside a query.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FriLayer {
    /// Offset from the start of a query.
    pub base: usize,
    /// Bytes this layer occupies.
    pub stride: usize,
    /// The layer's Merkle depth.
    pub depth: usize,
    /// Values under one leaf: the fold radix.
    pub count: usize,
}

/// Everything a verifier generator needs, and nothing it has to derive.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Manifest {
    pub params_id: [u8; 32],
    pub total_len: usize,
    pub ln: u32,
    pub fold_log: u32,
    pub digest_bytes: usize,
    pub n_queries: usize,
    pub trace_width: usize,
    pub n_periodic: usize,
    pub n_ood: usize,
    pub n_final: usize,
    pub tree_depth: usize,
    pub fri_base: usize,
    pub fri_stride: usize,
    pub cons_base: usize,
    pub cons_stride: usize,
    pub sidecar_base: usize,
    pub sidecar_stride: usize,
    pub perm_base: usize,
    pub perm_stride: usize,
    pub fri_layers: Vec<FriLayer>,
}

impl Layout {
    /// The layout as flat data, in the order `id` hashes it.
    pub fn manifest(&self) -> Manifest {
        let mut fri_layers = Vec::with_capacity(self.fri_layers);
        let mut base = 4;
        for m in 0..self.fri_layers {
            let stride = self.layer_bytes(m);
            fri_layers.push(FriLayer {
                base,
                stride,
                depth: self.fri_depth(m),
                count: 1usize << self.fri_fold_log,
            });
            base += stride;
        }
        Manifest {
            params_id: self.params_id,
            total_len: self.end,
            ln: self.log_domain,
            fold_log: self.fri_fold_log,
            digest_bytes: self.digest_bytes,
            n_queries: self.n_queries,
            trace_width: self.trace_width,
            n_periodic: self.n_periodic,
            n_ood: self.n_ood,
            n_final: self.n_final,
            tree_depth: self.tree_depth,
            fri_base: self.fri.base,
            fri_stride: self.fri.stride,
            cons_base: self.cons.base,
            cons_stride: self.cons.stride,
            sidecar_base: self.sidecar.base,
            sidecar_stride: self.sidecar.stride,
            perm_base: self.perm.base,
            perm_stride: self.perm.stride,
            fri_layers,
        }
    }

    /// The geometry as an ordered list of named 64-bit values.
    ///
    /// This is the single source both the identity hash and the Solidity
    /// emitter read. A field cannot reach one and miss the other, and the
    /// order cannot differ between them, because there is only one order.
    pub fn words(&self) -> Vec<(String, u64)> {
        let m = self.manifest();
        let named = |s: &str| alloc::string::ToString::to_string(s);
        let mut w: Vec<(String, u64)> = alloc::vec![
            (named("TOTAL_LEN"), m.total_len as u64),
            (named("LN"), m.ln as u64),
            (named("FOLD_LOG"), m.fold_log as u64),
            (named("DIGEST_BYTES"), m.digest_bytes as u64),
            (named("N_QUERIES"), m.n_queries as u64),
            (named("TRACE_WIDTH"), m.trace_width as u64),
            (named("N_PERIODIC"), m.n_periodic as u64),
            (named("N_OOD"), m.n_ood as u64),
            (named("N_FINAL"), m.n_final as u64),
            (named("TREE_DEPTH"), m.tree_depth as u64),
            (named("FRI_BASE"), m.fri_base as u64),
            (named("FRI_STRIDE"), m.fri_stride as u64),
            (named("CONS_BASE"), m.cons_base as u64),
            (named("CONS_STRIDE"), m.cons_stride as u64),
            (named("SIDECAR_BASE"), m.sidecar_base as u64),
            (named("SIDECAR_STRIDE"), m.sidecar_stride as u64),
            (named("PERM_BASE"), m.perm_base as u64),
            (named("PERM_STRIDE"), m.perm_stride as u64),
            (named("FRI_LAYER_COUNT"), m.fri_layers.len() as u64),
        ];
        /*
         * Each layer becomes four flat constants rather than an array,
         * because the generated Solidity reads a literal for free where an
         * indexed array costs memory. The names are formed from the index so
         * there is no ceiling: radix two at this degree bound produces
         * thirteen layers, which a fixed table of twelve did not survive.
         */
        for (i, f) in m.fri_layers.iter().enumerate() {
            w.push((alloc::format!("FRI_L{i}_BASE"), f.base as u64));
            w.push((alloc::format!("FRI_L{i}_STRIDE"), f.stride as u64));
            w.push((alloc::format!("FRI_L{i}_DEPTH"), f.depth as u64));
            w.push((alloc::format!("FRI_L{i}_COUNT"), f.count as u64));
        }
        w
    }

    /// The geometry's identity: keccak over the tag, the parameter identity,
    /// then every word in `words` order as a **big endian** u64.
    ///
    /// Big endian, and eight bytes each, because the point of this hash is
    /// that a generated Solidity library recomputes it from the constants it
    /// actually compiled in. `abi.encodePacked` over `uint64` is big endian,
    /// so the EVM side is one expression instead of twenty-three byte
    /// reversals, and a transcription error in the generated file changes the
    /// digest rather than hiding.
    pub fn id(&self) -> [u8; 32] {
        keccak256(&self.id_preimage())
    }

    /// The bytes `id` hashes, so a port that disagrees can compare encodings
    /// rather than digests.
    pub fn id_preimage(&self) -> Vec<u8> {
        let w = self.words();
        let mut buf = Vec::with_capacity(LAYOUT_DOMAIN.len() + 32 + 8 * w.len());
        buf.extend_from_slice(LAYOUT_DOMAIN);
        buf.extend_from_slice(&self.params_id);
        for (_, v) in w {
            buf.extend_from_slice(&v.to_be_bytes());
        }
        buf
    }
}
