# Security status: what is checked and what is not

This page lists every claim about the core that a test, a proof, a model check, a measurement or a
transaction backs, and every claim that nothing backs yet. Each line names what says so. Every other
page in this repository links here for its status.

The pool is the NOX Shield production pool on Sepolia, `0xaEe51E82965Ec1DeD870F3f4c248Ad4AdDc3e1cb`,
with its fee policy `0x660f66ab31Ca9919D9e1770FEDc88Ff2dd29CE59` and its verifier
`0xDA9dD4A3e957AFD2179131273C93dabBA1186A44`. The measurements below were taken on 1 October 2026 on
a machine of 4 virtual cores, an Intel Xeon at 2.10 GHz, with nothing else running. The build server
of the project was not reachable from that session, so no number here is a build server number.

## The production prover

| What | Evidence |
|---|---|
| The prover crates in `vendor/` differ in no file from the STARK repository at `e8f02a0` | `diff -rq` of `nox_prover`, `nonos-stark` and `stark_proofs` against a checkout of `e8f02a0` |
| `1b4b5a3` changes neither the prover, the field nor the vectors | `git diff --stat e8f02a0 1b4b5a3 -- nox_prover nonos-stark spec/wallet-vectors-not-before` is empty |
| The four pinned 37-limb vectors prove byte for byte, in format 5 and format 7, and cut to the single-call layout | `core/tests/prod_vectors.rs`: 95,496, 94,760, 95,496 and 95,752 bytes, the four in 321.9 s at a peak of 1,372 MB |
| The production verifier accepts the four single-call layouts | `verifyBatch` on `0xDA9d…6A44`, read with `eth_call` at the head of 1 October: `true` for each, at 3,873,458, 3,845,205, 3,873,095 and 3,884,565 gas estimated |
| A proof from the periodic cache, phase by phase | `core/tests/profile_prod.rs`: 67.7 s and 67.9 s, peak 845 MB and 876 MB. FRI 56%, the region commit 17%, the products 9%, DEEP 5%, the composition tree 5%. From nothing it is 82.7 s at 1,310 MB |
| The fixture seed the profile call carries spends nothing | `isKnownRoot` on the production pool at block 11,821,196: false for the root of the vector, `0x87c0…0757`, and true for its own `currentRoot()`. The secrets are the small integers 1617 to 1620, marked in the file as fixture secrets |
| The profile call proves the vector it names, and its times account for the whole proof | `the_vector_proves_and_its_times_add_up` in `core/tests/profile_vector.rs`, three runs on 1 October, each matching `proof.json` byte for byte with the eleven phases in order, the phases and the time after Verified 5 µs short of the total. On every core from the cache: 80.18 s, of which FRI 54%, the region 18%, the products 11%, and 2.51 s after Verified, peak 850 MB. On two threads: 137.75 s, of which FRI 56%, the region 18%, the products 10%, and 3.79 s after Verified, peak 883 MB. The first run built the cache before its proof, while ten fuzzers held most of the machine |

## The fee, the deposit and the rewards link

| What | Evidence |
|---|---|
| A fee is the protocol part plus one rung, split as the policy splits it | `the_split_names_the_protocol_part_and_the_rung` in `core/src/net/fee_schedule_test.rs`, and `settlementFee` on the policy, which returned the same split for the four vectors on 1 October |
| A spend proves the fee it was quoted, or none | `a_spend_proves_the_fee_it_was_quoted_or_none` in `core/src/ffi/wallet/quote_test.rs` |
| A typed amount becomes the fewest standard deposits, and every split adds up | `core/src/wallet/deposit_split_test.rs`: every whole number of cents from 0.01 to 100 ETH |
| The policy takes every split size, and refuses a size that is not standard | `depositFee` on the policy for 0.2, 0.1, 0.05, 0.02 and 10 ETH and five NOX sizes, and `NonStandardAmount` for 0.015 ETH |
| A batch of deposits goes out on consecutive nonces, one wei short refuses all of it, and a nonce at the top of its range is refused without a panic | `core/src/evm/shield_batch_test.rs` |
| The rewards link digest is the digest the registry computes | `domainSeparator()` and `linkDigest` of `0xf1DC…4225`, read live, in `core/src/wallet/rewards/rewards_test.rs` |
| A link signature is the signature Foundry makes, and its calldata is the calldata Foundry encodes | `cast wallet sign --data` and `cast calldata`, pinned in `rewards_test.rs` and `rewards_calls_test.rs` |
| The registry takes that link | `link` simulated with `eth_call` from the testnet address on 1 October, for a self link and a link to a second address: no revert |
| A link the registry would refuse is refused before review | `core/src/wallet/rewards/check_test.rs` |

## Open settlement

| What | Evidence |
|---|---|
| A published spend is republished after 15 minutes and offered to its owner after 30, and lands only when both nullifiers settle in one transaction | `core/src/wallet/publish/publish_test.rs` |
| The record of a publication reads back, and anything else is refused | the same file |
| Self settlement is refused for the first 30 minutes after a publication while a lander is on | `self_settle_open` in `core/src/ffi/wallet/follow.rs`, called from `review_self_settle` |
| The first settlement on the production pool, through its lander | [`0x93bd48ea…ec0d`](https://sepolia.etherscan.io/tx/0x93bd48eab8253ce497afbdc3fca7071a1d24a73599c866bd599101e301d2ec0d), block 11,817,581, 3,934,660 gas, before open settlement was written |

## Checked by the model checker

Kani 0.68.0 proves these for every input. `cargo kani -p nox_shield_core --lib` with the seven
harnesses below took 2 min 29 s, with 0 failures. The `kani` job of the `check` workflow runs them
once that workflow is enabled again.

| Harness | What holds for every input |
|---|---|
| `an_offer_is_always_one_the_chain_accepts_and_never_overpays` | the fee cap stays under 1,000 gwei, the tip under 5 gwei, and the tip never above the cap |
| `a_gas_limit_is_exact_for_ether_and_never_below_the_estimate` | ether to an address with no code gets 21,000, anything else never less than the estimate |
| `every_header_announces_its_own_length` | every RLP length prefix decodes back to its length |
| `every_integer_is_minimal_and_decodes_back` | every RLP integer has no leading zero and decodes back |
| `what_arrives_and_the_fee_add_up_to_what_was_sent` | a NOX transfer that passes delivers the amount less a fee below it, and a paused or blocked token passes nothing |
| `any_revert_data_reads_as_a_sentence_without_panicking` | any revert data up to 100 bytes gives a sentence |
| `a_send_that_passes_the_balance_check_is_always_covered` | an ETH, NOX or USDC send that passes is covered by the balance |

An eighth harness, `any_short_reply_is_read_or_refused_without_panicking`, feeds the account reply
reader every string up to 8 bytes. It does not finish and is not counted. The `account` fuzz target
reaches the same reader.

## Proved in Lean

| What | Evidence |
|---|---|
| 20 theorems about the Rust in `verified/src`, through Charon and Aeneas, on the three axioms of Lean only | `lean-verified/*Proofs.lean`, `lake build` and `#print axioms` on 1 October |
| Six of them about the fee arithmetic of a public send: the token fee adds back, a fee of the whole is refused, the offer is held to its ceiling and refused past it, the nonce is the larger, and the cover check is the true sum | `lean-verified/FeeProofs.lean` |
| 24 theorems about models of the store, the plan, the seed, the filter and the wipe | `lean/Shield/*.lean`, `lake build` on 1 October |
| The committed Lean translation matches what the Rust produces | `nix build .#checks.x86_64-linux.extraction`, in the `verify` workflow. Not run in this session |

## Reviewed by hand on 1 October

| What | Finding |
|---|---|
| Every `unsafe` in the code this repository owns | four volatile wipes, each through a valid `&mut`, and the opt-in aarch64 multiply, registers only. All sound |
| Every `unsafe` in `vendor/` | `nox_prover` compiles its C functions `nox_prove`, `nox_prove_ex`, `nox_verify` and `nox_free` into every build, so they reach the phone libraries: `llvm-nm -D` of both Android libraries lists them as the four exports outside the 331 of the uniffi binding. Reported to the prover team, since nothing in `vendor/` is edited here. Its allocator in `thread_cache.rs` builds only for threaded WebAssembly |
| Every place a secret lives in memory | the seed, the account key, the view key, the receiving key, a note opening and the proof entropy are wiped on drop. The seed file the prover reads was built from temporary strings, freed unwiped, and is now written in place into one buffer that never grows (`core/src/prover/launch/seed.rs`, `the_seed_file_is_written_in_place`). The prover itself keeps the witness in its own memory while it runs, as [02-threat-model.md](02-threat-model.md) says |
| Every network path | each new call goes through the embedded Tor client: the policy reads on the scan circuits, the registry reads and the deposits on the circuits of the account, the contract wallet check on the circuits of the mainnet account, the publication on the relay circuits. `scripts/check-one-destination.sh` passes |
| Every error path for a panic | clippy denies unwrap, expect, indexing, panics and unchecked arithmetic. Of what it does not see, every `split_at` and every `copy_from_slice` is bounded by a length checked before it. One panic was found and removed: a range of nonces that could pass the end of `u64` on a hostile reply, now `a_nonce_past_the_range_is_refused_not_panicked` |

## Checked on every run of the suite

| What | Evidence |
|---|---|
| Every unit and integration test passes | `cargo test --workspace --all-features`: 235 passed, and 18 ignored that need the network or the pinned vectors, on 1 October |
| Formatting and lints pass with warnings denied, with every feature and with none | `cargo fmt -p nox_shield_core -p nox_verified --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, and the same without features |
| Every parser survives every length and random content without a panic | `core/src/fuzz/sweep_test.rs`, over the ten fuzz entry points of [08-fuzzing.md](08-fuzzing.md) |
| The dependency set is an allowlist, nothing logs, nothing names a network address outside `core/src/net`, nothing makes an identifier | the four scripts in `scripts/`, all passing on 1 October |

The `check`, `privacy` and `verify` workflows of the core have been disabled by hand since
26 September, and the core commits carry `[skip ci]`. Each workflow now has a `workflow_dispatch`
trigger, so once they are enabled again a run is one request, and the `reproduce` workflow joins
them when this branch reaches `main`.

## Not checked

- **Publishing to the public Waku topic.** The publish specification of 1 October was not in reach
  of this session, so the core publishes through the lander onion only. The Waku route goes first
  once its topic, entry node and payload are known.
- **A spend published and landed through open settlement.** Tor could not start where this work
  was done, so no publication left a device and none landed.
- **The proving time on a phone.** It is published only as the median of three runs on one device,
  each proof accepted by the live verifier, with the device, the build and the thermal state.
  `profile_proof` has not run on a phone yet.
- **A packet trace from a device.** The network claims in [03-transport.md](03-transport.md) are
  claims about the code until a trace shows a passive observer sees Tor and nothing else.
- **24-hour fuzz runs on the build server.** What ran, and for how long, is in
  [08-fuzzing.md](08-fuzzing.md).
- **The iOS archives, built twice.** The `ios` job of the `reproduce` workflow builds them on macOS
  and compares them. It has not run. The Android result is in [07-reproduce.md](07-reproduce.md).
- **A Tamarin model** of note sealing and the hand-off, and a formally verified ML-KEM inside
  X-Wing. Not started.
- **The account vectors, reproduced independently,** and **that `nk` grants no power to spend.**
  See [09-accounts.md](09-accounts.md).
- **An external audit.** None, of the core, the apps or the pool.
- **A shield on mainnet.** The pool runs on Sepolia only, until an audit.
- **The governance of the pool.** What its owner can and cannot do is a property of the pool
  contract, which lives in its own repository.

## The commands

```sh
cargo fmt -p nox_shield_core -p nox_verified --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
PROD_VECTORS=path/to/wallet-vectors-not-before PROD_VECTORS_OUT=/tmp/out \
    cargo test --release -p nox_shield_core --test prod_vectors -- --ignored --nocapture
PROD_VECTORS=path/to/wallet-vectors-not-before PROD_CACHE=/tmp/periodic.bin \
    cargo test --release -p nox_shield_core --test profile_prod -- --ignored --nocapture
cargo kani -p nox_shield_core --lib --harness <name>
(cd lean && lake build)
(cd lean-verified && lake build)
scripts/reproduce.sh android
for s in scripts/check-*.sh; do "$s"; done
cargo deny check && cargo audit
```

The profile runs twice: the first proves from nothing and keeps the periodic cache, and the second
proves from it and prints each phase.
