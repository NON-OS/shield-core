// NONOS Operating System (AGPL-3.0-or-later)
//! Every parameter point that clears the provable soundness floor and fits
//! both ceilings, cheapest to prove first.
//!
//! This decides nothing. It replaces four points somebody thought of with
//! every point there is, so the choice is made from a table rather than from
//! the order the ideas arrived in. The gas column is a model with named
//! coefficients and it is wrong by whatever factor the profile says; what it
//! is for is ranking, where a uniform error cancels.
//!
//!     cargo run --release --bin search_points
//!     cargo run --release --bin search_points -- --rows 40 --min-provable 96
//!
//! The shipped point is printed at the bottom whether or not it ranks, so a
//! reader can see what the alternatives are alternatives to.

use stark_proofs::budget::{evaluate, search, CostModel, Evaluated, Limits, Point};
use stark_proofs::proof_wire::ParamSet;

fn arg(name: &str, default: u64) -> u64 {
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        if a == name {
            return it
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| panic!("{name} wants a number"));
        }
    }
    default
}

/// The circuit. Not searched: these are what the statement is, not how it is
/// proved, and moving them means a different relation.
fn circuit() -> ParamSet {
    ParamSet {
        n_queries: 12,
        grind_bits: 32,
        extra_blowup_bits: 7,
        fri_fold_log: 2,
        fri_stop_log: 8,
        digest_bytes: arg("--digest-bytes", 24) as u32,
        trace_width: arg("--trace-width", 41) as u32,
        n_periodic: arg("--n-periodic", 119) as u32,
        log_trace_len: arg("--log-trace-len", 18) as u32,
        constraint_degree: arg("--constraint-degree", 8) as u32,
        window_size: arg("--window-size", 2) as u32,
        num_transition: arg("--num-transition", 37) as u32,
        n_boundary: arg("--n-boundary", 723) as u32,
        coset_shift: 7,
        commit_grind_bits: 0,
        grind_chunks: 1,
    }
}

fn shipped() -> Point {
    Point {
        n_queries: 12,
        extra_blowup_bits: 7,
        grind_bits: 32,
        fri_stop_log: 8,
        fri_fold_log: 2,
    }
}

fn header() {
    println!(
        "{:>3} {:>2} {:>5} {:>4} {:>4} {:>3} {:>3} {:>8} {:>7} {:>10} {:>10} {:>7}",
        "q", "R", "grind", "stop", "fold", "LN", "L", "bytes", "prov", "modelled", "headroom",
        "prove"
    );
    println!("{}", "-".repeat(78));
}

fn row(e: &Evaluated) {
    println!(
        "{:>3} {:>2} {:>5} {:>4} {:>4} {:>3} {:>3} {:>8} {:>7} {:>10} {:>10} {:>6}%",
        e.point.n_queries,
        e.rate_exponent,
        e.point.grind_bits,
        e.point.fri_stop_log,
        1 << e.point.fri_fold_log,
        e.log_domain,
        e.fri_layers,
        e.bytes,
        e.provable_bits,
        e.modelled_verify_gas,
        e.headroom,
        e.proving_relative_permille / 10,
    );
}

fn main() {
    let c = circuit();
    let model = CostModel::default();
    let limits = Limits {
        min_provable_bits: arg("--min-provable", 80) as u32,
        max_bytes: arg("--max-bytes", 131_072),
        max_grind_bits: arg("--max-grind", 32) as u32,
        max_log_domain: arg("--max-log-domain", 30) as u32,
        /*
         * Radix four is what the prover implements. Widening this reports
         * points nobody can prove today, which is worth knowing and is not a
         * decision: the first run of this search put radix eight at the top
         * of the table by a wide margin.
         */
        fold_log_range: (arg("--min-fold-log", 2) as u32, arg("--max-fold-log", 2) as u32),
    };
    let rows = arg("--rows", 25) as usize;

    let all = search(&c, &model, &limits);
    println!(
        "circuit   width {}, 2^{} rows, degree {}, {} transitions, {} periodic",
        c.trace_width, c.log_trace_len, c.constraint_degree, c.num_transition, c.n_periodic
    );
    println!(
        "limits    provable >= {}, bytes <= {}, grind <= {}, domain <= 2^{}",
        limits.min_provable_bits, limits.max_bytes, limits.max_grind_bits, limits.max_log_domain
    );
    println!(
        "admissible points: {}   (R is the rate exponent, prove is work against the shipped point)",
        all.len()
    );
    println!();
    header();
    for e in all.iter().take(rows) {
        row(e);
    }
    if all.len() > rows {
        println!("... {} more", all.len() - rows);
    }

    println!();
    println!("the point we ship, for comparison:");
    header();
    match evaluate(&c, &shipped(), &model, &limits) {
        Ok(e) => {
            row(&e);
            let rank = all.iter().position(|x| x.point == shipped()).map(|i| i + 1);
            match rank {
                Some(r) => println!("\nit ranks {r} of {} on proving cost", all.len()),
                None => println!("\nit is not in the list, which should not happen"),
            }
        }
        Err(why) => println!("inadmissible under these limits: {why}"),
    }
}
