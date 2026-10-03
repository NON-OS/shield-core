// NONOS Operating System (AGPL-3.0-or-later)

//! The settlement outer as the wrap's inner: assembled by name, proved under
//! Poseidon, packed. Proving it is most of an hour on a large server and the proof
//! is the same every time, so a directory can hold it: named, the proof is
//! read back and verified against the circuit as it now is; absent, empty,
//! or made under an earlier transcript, it is proved and stored there.

use crate::crypto::stark::air::{
    periodic_root_poseidon, stark_prove_poseidon_pre_rounds, stark_verify_poseidon_rounds,
    OuterRegion, Poseidon, WiredMultiGen,
};
use crate::proof_wire::{deserialize_p_rounds, serialize_p_rounds};
use crate::recursion_assembly::anchors::Anchors;
use crate::recursion_assembly::inner::{pack_air, shield_join_split, Inner, EXTRA, GRIND, NQ};
use crate::recursion_assembly::point::Point;
use crate::shield_params::rehearsal::under_wrap;
use crate::recursion_assembly::{assemble_over_gen, AssemblyGen, Tamper};
use std::path::Path;

/// The wrap's inner, by type.
pub type OuterInner = Inner<WiredMultiGen<OuterRegion<WiredMultiGen>>>;

/// The settlement outer over the shield inner, regions held by name, with the
/// anchors collapsed: the shape a wrap is priced against. `cap` is how many
/// of the inner's queries it attests; `usize::MAX` is every one.
pub fn typed_outer(h: &Poseidon, cap: usize) -> AssemblyGen<WiredMultiGen> {
    assemble_over_gen(
        h,
        shield_join_split(h),
        Tamper::None,
        cap,
        Point::emit_wiring(),
        Anchors::Collapsed,
    )
}

/// The point the outer is proved at under Poseidon, as the wrap's inner.
#[derive(Clone, Copy, Debug)]
pub struct OuterPoint {
    pub nq: usize,
    pub grind: u32,
    pub extra: u32,
}

impl OuterPoint {
    /// The deployment point: what the chain verifies the outer at today.
    pub const DEPLOYMENT: OuterPoint = OuterPoint { nq: NQ, grind: GRIND, extra: EXTRA };
    /// The outer under the one-transaction wrap: sixteen queries at rate
    /// 1/64 with the 32-bit grind, 128 conjectured and 80 provable, so the
    /// wrap carries half the per-query rows it carried at thirty-two.
    pub const UNDER_WRAP: OuterPoint = OuterPoint {
        nq: under_wrap::N_QUERIES,
        grind: under_wrap::GRIND_BITS,
        extra: under_wrap::EXTRA_BLOWUP_BITS,
    };
}

/// The typed outer proved under Poseidon at the deployment point and packed
/// as an inner, from the cache directory when it holds the proof.
pub fn packed_outer(h: &Poseidon, cap: usize, cache: Option<&Path>) -> OuterInner {
    packed_outer_at(h, cap, cache, OuterPoint::DEPLOYMENT)
}

/// The same at a named point. The cache entry carries the point in its
/// name, and a cached proof is verified against the circuit as it now is
/// before it is packed: one from before a change packs as a witness that
/// fails after the whole assembly, so it is refused here and proved again.
pub fn packed_outer_at(h: &Poseidon, cap: usize, cache: Option<&Path>, point: OuterPoint) -> OuterInner {
    let mut asm = typed_outer(h, cap);
    let publics = asm.publics.clone();
    let root = periodic_root_poseidon(&asm.gen, point.extra, h);
    // Every query when the outer is whole; a few when it is capped for a gate.
    let nq = if cap == usize::MAX { point.nq } else { 8 };
    let name = if cap == usize::MAX {
        format!("typed-outer-full-q{}-g{}-e{}.p", point.nq, point.grind, point.extra)
    } else {
        format!("typed-outer-cap{cap}-g{}-e{}.p", point.grind, point.extra)
    };
    let path = cache.map(|d| d.join(name));
    if let Some(p) = path.as_ref().filter(|p| p.exists()) {
        let bytes = std::fs::read(p).expect("the cached proof reads");
        let rounds = deserialize_p_rounds(&bytes).expect("the cached proof parses");
        if stark_verify_poseidon_rounds(&mut asm.gen, &rounds, nq, point.grind, point.extra, h, &publics, &root) {
            std::eprintln!("typed outer: proof read from {} and verified", p.display());
            drop(core::mem::take(&mut asm.witness));
            return pack_air(h, asm.gen, rounds, publics, root, point.extra, point.grind);
        }
        std::eprintln!("typed outer: the proof at {} is not this circuit's; proving again", p.display());
    }
    let mut witness = core::mem::take(&mut asm.witness);
    let Some((rounds, air)) = stark_prove_poseidon_pre_rounds(
        asm.gen,
        &mut witness,
        nq,
        point.grind,
        point.extra,
        h,
        &publics,
        &[],
    ) else {
        panic!("the typed outer carries no permutation columns above its regions");
    };
    drop(witness);
    if let Some(p) = path {
        let _ = std::fs::write(&p, serialize_p_rounds(&rounds));
        std::eprintln!("typed outer: proof stored at {}", p.display());
    }
    pack_air(h, air, rounds, publics, root, point.extra, point.grind)
}
