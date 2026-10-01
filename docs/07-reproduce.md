# Reproducing the core

How to rebuild the core from source and get the same bytes, with every pinned version and where it is
pinned. Both apps link the same core, so a reader who rebuilds it rebuilds the logic of the wallet
once for both platforms. What is checked and what is not is in
[20-security-status.md](20-security-status.md).

Everything the core compiles is in this repository: its own crates, and
the prover and custody sources in `vendor/`, copied in at pinned commits. A build fetches crates
from crates.io and nothing else.

## What is pinned

| Component | Version | Where it is pinned |
|---|---|---|
| Rust | 1.91.1, with rustfmt and clippy | `rust-toolchain.toml` |
| Every crates.io crate | exact versions | `Cargo.lock`, and direct dependencies with `=` in `Cargo.toml` |
| The prover: `nonos-stark`, `stark_proofs`, `nox_prover` | the STARK repository at `e8f02a0`, tarball SHA-256 `dc147f96…0748`, built with the `not_before` feature | `vendor/`, recorded in `vendor/README.md` |
| The custody crates: `nonos_hd`, `nonos_seal` | source at `51ceb73b7` | `vendor/`, recorded in `vendor/README.md` |
| Lean | 4.31.0 | `lean/lean-toolchain`, `lean-verified/lean-toolchain` |
| Charon and Aeneas | Aeneas commit `45061fa`, and the Charon it exports | `flake.nix`, `flake.lock` |
| nixpkgs | `nixos-25.05` | `flake.nix`, `flake.lock` |
| TLA+ tools | 1.8.0, SHA-256 `32d64fbbc464559fc7192341b27b885fa4eb6b92d1648d2b49fb9cdcb7aacf81` | `spec/check.sh` checks the hash before running |
| The verification kit | tarball SHA-256 `c63e192304bee55880bdced6ea13169c8d89c9e8192aa46562a587660ee2cbc4` | `ci/verify-kit.source`, and every file in `ci/verify-kit/SHA256SUMS` |
| The Android NDK | 27.0.12077973, r27, with `cargo-ndk` 4.1.2 | `.github/workflows/reproduce.yml`, and the flake of the Android app |
| Kani | 0.68.0 | `.github/workflows/check.yml` |

The dependency set is an allowlist: `scripts/dependencies.allow` names every crate the build may
reach, 507 of them, and `scripts/check-dependencies.sh` recomputes the set from `Cargo.lock` and
fails on any difference. `deny.toml` refuses any registry other than crates.io.

## The release profile

`Cargo.toml` builds releases with `opt-level = 3`, fat LTO, one codegen unit, `panic = "abort"`,
symbols stripped, no debug information, and overflow checks kept on. One codegen unit and no debug
information are what make two builds of one commit produce the same bytes. The app build scripts
also remap every local path prefix (`--remap-path-prefix` for Rust, `-ffile-prefix-map` for C), so
no path of the machine that built a library ends up inside it. The iOS script also searches the
finished library for the home directory of the build and fails if it finds it.

## Steps

```sh
cargo fmt -p nox_shield_core -p nox_verified --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo build --release -p nox_shield_core
sha256sum target/release/libnox_shield_core.a
```

The phone libraries are built by the app repositories, from the core commit their `core.lock` names:
`scripts/build-core.sh` in each refuses to build any other commit. The Android repository runs the
same build twice from clean in its `reproduce` workflow and fails if the two packages differ.

## The phone libraries, built twice

`scripts/phone-libs.sh android|ios` builds the libraries the apps ship with the flags their build
scripts use: the release profile, every local path remapped (`--remap-path-prefix` for Rust,
`-ffile-prefix-map` for C), `ZERO_AR_DATE` and `SOURCE_DATE_EPOCH` set, and a refusal if the home
directory of the builder is still inside a library. `scripts/reproduce.sh` makes two worktrees of
the commit in two directories, builds each from clean, and compares the hashes. A difference fails
and prints the first bytes that differ.

```sh
ANDROID_NDK_HOME=path/to/android-ndk-r27 scripts/reproduce.sh android
scripts/reproduce.sh ios                     # on macOS, with Xcode
```

The `reproduce` workflow runs both, on Linux and on macOS, by hand and on a tag.

| Library | Commit | SHA-256, both builds | Where |
|---|---|---|---|
| Android, arm64-v8a | `f9a7e63` | `8d6b858bee9fd107bedd9d43c57e7ba07e71f5d767b80e291daddb0135a69f14` | 4 virtual cores, Linux, NDK r27, cargo-ndk 4.1.2, 1 October |
| Android, x86_64 | `f9a7e63` | `da6f9cda28c45dc288dbabcc78b31851889ae8b07a47e3de4b84927db2810129` | the same run |
| iOS, device and simulator | | not built yet | the `ios` job of the `reproduce` workflow, on macOS |

The two Android builds ran from clean in two worktrees, one after the other, and took 81 minutes
with ten fuzzers running beside them. The arm64-v8a library is 11,481,664 bytes and the x86_64
one 13,010,464. Neither names a path of the machine that built it: their only paths start with
`/cargo`, `/nox-shield-core` or `/rustc`. A hash holds for its commit only. A later commit that
changes a doc comment on an exported call changes the library, because the binding carries its
documentation: the doc comment of `bench_proof` is in both files.

## The Lean translation

`lean-verified/NoxVerified.lean` is generated from `verified/src` and committed. To regenerate it
with the pinned tools:

```sh
nix build .#extraction
cp result/NoxVerified.lean lean-verified/NoxVerified.lean
```

The `verify` workflow runs `nix build .#checks.x86_64-linux.extraction`, which fails if the
committed file differs from what the Rust produces, and uploads the regenerated file when it does.

## Updating the vendored source

A vendored crate moves forward only as a whole: its directory is replaced with the new source from
a published tarball whose SHA-256 is checked, the commit and the hash go into `vendor/README.md`,
and the full gate runs, including the pinned proofs of the image verified by the new prover. Nothing is edited
inside `vendor/` by hand, because a change made only in this copy is one the next update discards.
`cargo fmt` is run on the core crates by name for the same reason: formatting the whole workspace
would rewrite the vendored files.
