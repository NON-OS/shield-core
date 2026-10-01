// NONOS Operating System (AGPL-3.0-or-later)
//! What a shipped artifact is, read from the artifact.
//!
//! A verifier's author should not have to reconstruct a proof's shape from
//! raw bytes. This parses a complete two round artifact with the strict
//! reader and prints what it found: the shape a verifier must be generated
//! at, and the sha256 that names the file.
//!
//! It refuses what the chain must refuse. A file that prints here is a file
//! whose every field element is canonical, whose every count agrees with the
//! counts the proof already carries, and which has no bytes after its last
//! section.

use stark_proofs::crypto::stark::merkle::DIGEST_BYTES;
use stark_proofs::proof_wire::{deserialize_rounds_legacy, read_header};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: read_artifact <proof>");
        std::process::exit(2);
    });
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        eprintln!("cannot read {path}: {e}");
        std::process::exit(2);
    });
    // A tool establishes provenance; it does not judge it. Production
    // verification takes one format and refuses the rest, which is why this
    // is the only place a headerless artifact is read at all.
    let hdr = read_header(&bytes);
    let body = match hdr {
        Some(_) => &bytes[stark_proofs::proof_wire::HEADER_BYTES..],
        None => {
            println!("header          none: produced before the format described itself");
            &bytes[..]
        }
    };
    let Some(p) = deserialize_rounds_legacy(body) else {
        eprintln!("{path}: not a complete artifact at {DIGEST_BYTES} byte digests");
        eprintln!("  a truncation, a trailing byte, a non canonical element, or another codec");
        std::process::exit(1);
    };
    if let Some(h) = hdr {
        println!("format          {}", h.format);
        println!("protocol        {}", h.protocol);
        println!("paramSetId      {}", hex(&h.params));
    }

    let pre = &p.pre;
    let q = &pre.proof.queries;
    let fri = &pre.proof.fri;
    let width = q.first().map(|x| x.trace.len()).unwrap_or(0);
    let layers = q.first().map(|_| fri.queries[0].layers.len()).unwrap_or(0);
    let depth = q.first().map(|x| x.trace_path.len()).unwrap_or(0);

    println!("file            {path}");
    println!("bytes           {}", bytes.len());
    println!("digest bytes    {DIGEST_BYTES}");
    println!("permRoot        {}", hex(&p.perm_root[..DIGEST_BYTES]));
    println!("regionWidth     {}", p.region_width);
    println!("traceRoot       {}", hex(&pre.proof.trace_root[..DIGEST_BYTES]));
    println!("compRoot        {}", hex(&pre.proof.comp_root[..DIGEST_BYTES]));
    println!("traceWidth      {width}");
    println!("nPeriodic       {}", pre.periodic_z.len());
    println!("oodFrame        {}", pre.proof.ood_frame.len());
    println!("queries         {}", q.len());
    println!("friRoots        {}", fri.roots.len());
    println!("friLayers       {layers}");
    println!("finalLayer      {}", fri.final_layer.len());
    println!("treeDepth       {depth}");
    println!("sidecarOpenings {}", pre.openings.len());
    println!("permPaths       {}", p.perm_paths.len());
    println!("grindNonce      {}", fri.pow_nonce);
    /*
     * The trace, composition, sidecar and permutation trees all commit one
     * leaf per evaluation point, so a domain of 2^LN points gives a tree of
     * depth LN; the DEEP value opens in FRI layer zero, two levels shorter. This printed depth + 1 until 2026-09-22, which says a
     * domain is twice its real size; the FRI layer depths are LN - 2 - 2m and
     * reading them against the inflated LN produced an off-by-one in every
     * layer of a hand-written offset table. The relation is asserted against
     * a real artifact by tools/walk_offsets.py, which derives LN from the
     * circuit rather than from a tree it is trying to check.
     */
    println!("logDomain       {depth}");
}
