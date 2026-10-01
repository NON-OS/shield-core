# Proofs about models of the wallet

What the wallet must get right in ordinary arithmetic and bookkeeping, stated as theorems and
checked by Lean. There are 24 theorems in seven files, and the CI job `lean` builds them on every
push.

| File | Theorems | What they prove |
|---|---|---|
| `Shield/Amount.lean` | 4 | the amount codec round trips, and the fraction never carries into the whole |
| `Shield/Conserve.lean` | 4 | a plan balances, never mints, leaves the remainder as change, and an uncovered fee has no plan |
| `Shield/Seed.lean` | 4 | a blinding seed is accepted once, recorded, and refused every time after |
| `Shield/Store.lean` | 0 | the model the next file reasons about: rows, the fold, the balance |
| `Shield/StoreProofs.lean` | 6 | a found note is spendable and a spent one is not, a row replayed twice is one note, spending an unknown note changes nothing, the cursor never moves back, and replay is deterministic |
| `Shield/Filter.lean` | 2 | the discovery filter has no false negative, and passing it is not ownership |
| `Shield/WipeProofs.lean` | 4 | a wiped store is the empty store and has nothing to spend |

## What a model proof is worth

Everything under `Shield/` is about a model written by hand, small enough to read beside the Rust.
The correspondence between the model and the Rust is for a reader to check, and that is the
weakness of this kind of proof.

The second kind closes that gap for the code where it matters most. `../lean-verified` proves
theorems about `verified/src` itself: Charon reads the Rust as the compiler reads it, Aeneas
translates it into `NoxVerified.lean`, and the proofs are about that translation. `Shield/Amount.lean`
proves the amount codec over a model, and `../lean-verified/AmountProofs.lean` proves it over the
function the core calls. The two packages are separate because the Aeneas library needs mathlib,
which is fetched from the network, and this package needs nothing beyond the Lean core library, so
it builds offline.

## What is not proved here

The soundness of the STARK, the blinding and the constraint set of the circuit. Those belong to the
prover and its own proofs, and this wallet assumes them without restating them.

The cryptography is assumed too: ChaCha20-Poly1305, X25519, ML-KEM-768, SHA3, BLAKE3, Keccak and
Poseidon are taken as sound. What is proved here is how the wallet uses them.

## Build

```sh
lake build
```

Lean 4.31.0, as `lean-toolchain` pins it. No mathlib, so nothing is fetched. The proofs are short on
purpose: `omega` and `simp` over a model small enough to read are worth more than a long proof of
something nobody can restate.
