# The field kernel

A transfer proof is minutes of arithmetic in one field, the Goldilocks prime 2^64 - 2^32 + 1, and
almost all of it is one operation: a multiply, inside the Poseidon rounds and the number theoretic
transform. This crate holds that multiply twice, in portable Rust and in aarch64 assembly, with
tests that say they agree and a benchmark that says which is faster on the machine it runs on.

## Why it is here and not in the prover

The prover is a vendored crate, and its field arithmetic is on the trust path of every proof.
Replacing it is worth doing only if a measurement on a phone says so, so the candidate lives here
until there is that number. Nothing in the wallet calls this crate.

## What it claims, and what says so

| Claim | Test |
|---|---|
| The kernel agrees with the reference on the values a field bug hides behind | `tests/differential.rs`, the edge cases |
| They agree over a deterministic sweep of 20,000 pairs | `tests/differential.rs`, the sweep |
| Every result is canonical, in `[0, P)` | `tests/differential.rs` |
| The reference obeys the field laws, so it is not wrong in the same way as the kernel | `tests/laws.rs` |
| 2^64 folds to 2^32 - 1, the identity the reduction rests on | `tests/laws.rs` |
| Both agree with the field element of the prover, which is what a proof is made with | `tests/upstream.rs` |

```sh
cargo test -p nox_field_kernel                    # the portable path
cargo test -p nox_field_kernel --features kernel  # the assembly path, on aarch64 only
```

Both must pass. The kernel is behind a feature that is off by default, and the portable path is
what ships until a phone says otherwise.

## Where it stands

The portable path is tested. The assembly is tested only where it compiles, on aarch64, and it has
not been measured on a phone. It is not adopted.

## Which benchmark decides

`examples/kernel_bench` runs two workloads. The first is a chain of dependent multiplies, each
waiting on the last. The second has the multiply count and the dependency pattern of a Poseidon
permutation over 8 elements: an S-box at x^7 and a dense 8 by 8 matrix multiply per round, about
112 multiplies. It has no round constants and a fixed matrix, so it is a proxy for the cost, not
the permutation.

The second decides, because a proof spends almost all of its time in Poseidon
rounds, and the multiply is what those rounds are made of. A kernel that wins the chain and loses
the permutation-shaped workload would make proofs no faster.

```sh
cargo run --release -p nox_field_kernel --example kernel_bench                    # portable
cargo run --release -p nox_field_kernel --features kernel --example kernel_bench  # kernel
```

If the kernel does not clearly win the permutation-shaped row on a phone, it should be deleted:
assembly on a trust path is permanent maintenance and permanent audit surface.
