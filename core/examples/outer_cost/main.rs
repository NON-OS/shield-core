//! What it costs to build the outer verifier's circuit, without proving it.
//!
//! Verifying a settlement proof needs the outer AIR, which is the assembly
//! rather than the proving: 747 columns over a 2^18 trace, assembled from the
//! regions that replay an inner verification. A devnet is meant to start in a
//! second, so this measures the assembly before anything depends on it. If it
//! is minutes, a devnet builds it once at startup and holds it rather than
//! building one per verification.
//!
//! ```sh
//! /usr/bin/time -l cargo run --release --example outer_cost
//! ```

use stark_proofs::crypto::stark::air::Air;
use stark_proofs::recursion_assembly::inner::hasher;
use stark_proofs::recursion_assembly::tamper::Tamper;
use std::time::Instant;

fn main() {
    let h = hasher();

    let t0 = Instant::now();
    let inner = stark_proofs::recursion_assembly::inner::shield_join_split(&h);
    println!("inner proved and replayed in {:?}", t0.elapsed());

    let t1 = Instant::now();
    let outer = stark_proofs::recursion_assembly::build::assemble_over(&h, inner, Tamper::None, 1);
    let built = t1.elapsed();
    println!(
        "outer assembled in {built:?}: log_trace_len={} width={} degree={} periodic={} trace={}",
        outer.wired.log_trace_len(),
        outer.wired.trace_width(),
        outer.wired.constraint_degree(),
        outer.wired.periodic_columns().len(),
        outer.witness.len()
    );
}
