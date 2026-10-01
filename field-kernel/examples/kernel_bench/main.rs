//! Time the field multiply on this machine, with `--features kernel` and without, since the
//! difference is the whole case for the kernel. A dependent chain measures latency. The
//! permutation workload measures the prover's mix: a transfer proof spends 96 percent of its
//! time in the Poseidon round, an x^7 S-box layer plus a dense 8 by 8 matrix multiply.

mod chain;
mod permutation;

use nox_field_kernel::kernel_in_use;

fn main() {
    println!("kernel      {}", kernel_in_use());
    chain::run();
    permutation::run();
}
