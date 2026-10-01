# The prover's inputs and outputs

`nox_prover::prove_with(request, seed, entropy, &options)` proves one spend: two notes in and two
notes out. This is every field it reads, with its type and unit, and what it returns.
`spec/wallet-vectors/` holds pinned examples: a request, a seed file and fixed entropy, with the proof
and public words they produce. The Rust prover and the Zig client (`ocean/src/wallet_vectors_test.zig`)
agree on all of them.

Numbers are JSON integers. A digest is a 256-bit word, written `0x` followed by 64 hex digits:
limb 0 is the lowest 64 bits, as the pool stores it (`host::pack_u256`, `try_unpack_digest`). An
address is `0x` followed by 40 hex digits.

## The request

| field | type | meaning |
|---|---|---|
| `pool_leaves` | digests | every note commitment in the pool, in leaf order. The prover rebuilds the depth-32 tree and refuses the request unless its root is `note_root` |
| `note_root` | digest | the pool root the spend proves against, as the pool published it |
| `assoc_leaves` | digests | every leaf of the association set, in order |
| `assoc_root` | digest | the association set's root, as the registry published it |
| `input_pool_index` | two integers | the leaf index of each input note in `pool_leaves` |
| `input_assoc_index` | two integers | the leaf index of each input note in `assoc_leaves` |
| `output_values` | two integers | the value of each created note, in note units |
| `output_spend_pk` | two strings, optional | per output, the receiver's spend key as a digest, or `"self"`. Absent means both are the spender's |
| `public_amount` | integer | the value leaving the pool, in note units; 0 for a transfer |
| `fee` | integer | the relay fee, in note units, paid to `fee_recipient` |
| `fee_recipient` | address, optional | the submitter the fee pays. Required when `fee` is nonzero, refused when it is zero |
| `recipient` | address | where `public_amount` goes; all zero on a transfer |
| `clearing_price` | integer | the withdrawal's clearing price; 0 on a transfer |
| `asset_id` | integer | the asset, for the anonymity policy's unit: 0 is ETH, 1 is NOX |
| `self_submit` | `true`, optional | opt out of submission through a relay (policy) |
| `any_amount` | `true`, optional | opt out of standard sizes (policy) |
| `unit` | integer, optional | the smallest standard note in note units, overriding the asset table |

Other fields are ignored. Inputs must balance: `input_0 + input_1 = output_0 + output_1 +
public_amount + fee`, all as integers below p. A note worth zero is a dummy, and its indices are not
checked against the trees.

**Note units.** A note's value is in the pool's note units for its asset:

| asset | id | note unit | smallest standard note |
|---|---|---|---|
| ETH | 0 | 1 wei | 10^15 (0.001 ETH) |
| NOX | 1 | 10^9 base units | 10^6 (0.001 NOX) |

**The anonymity policy** (`src/policy.rs`, `ocean/ANONYMITY.md`):
- a spend pays a nonzero `fee` to a named `fee_recipient` unless `self_submit` is set;
- `public_amount`, and every output to someone else, is `unit × {1, 2, 5} × 10^k` unless
  `any_amount` is set.

Each opt-out is reported in the proof's `weakened`.

## The seed file

The spender's two notes and their secrets, as the wallet holds them:

| field | type | meaning |
|---|---|---|
| `secrets` | two lists of four integers | each note's spend secret, four field limbs. A wallet has one secret, so both are usually the same |
| `notes` | two objects | each note's `value`, `asset_id`, `spend_pk` (four integers) and `blinding` (four integers) |

Each note's commitment must be `pool_leaves[input_pool_index[i]]`, and its `spend_pk` must be the
one its secret derives.

## The entropy

Exactly `ENTROPY_BYTES` (512) bytes from the platform's CSPRNG, used once. They make the created
notes' secrets and blindings and the proof's blinding seed. Reusing entropy reuses secrets. The
pinned vectors use `(7 i + 3) mod 256` so that their proofs are reproducible; nothing else may.

## The options

| field | meaning |
|---|---|
| `cache` | the bundled periodic cache. It is refused unless its root is `PERIODIC_ROOT` |
| `progress` | called at each phase boundary with the phase and the fraction done |
| `cancel` | set to stop at the next phase boundary |

## What comes back

`prove_with` returns the proof and its 36 public words, or an `Error`: request, policy, entropy,
cache, circuit, not verified, rank, or cancelled. The proof is verified, and its zero-knowledge rank
certificate checked, before it is returned. `rank` means the certificate fell short (about one proof
in 2,044): nothing is returned, and the caller proves again with fresh entropy.
`to_json` renders it:

| field | meaning |
|---|---|
| `proof` | the proof bytes as hex, 112,956 bytes at the launch point |
| `publics` | the 36 public words in the pool's order: note root, association root, two nullifiers, two output commitments, public amount, fee, asset, clearing price, recipient (four 48-bit limbs), fee recipient (four limbs) |
| `outputs` | the two created notes with their leaf commitments; for each note the spender owns, its new secret |
| `grind_hashes` | the grinds' winning nonces added up: the proof-of-work the proof took |
| `rank` | the rank certificate the proof passed: `bound`, `certified` (equal on every returned proof) and `subsets`. A relayer can recompute it from the bytes with `zk_fri_rank_check`; it needs nothing secret |
| `weakened` | the anonymity defaults this request opted out of |

The JSON holds the spender's new note secrets. Store it as a secret.

The prover runs the rank check itself (docs/12-zero-knowledge.md, Section 4.4). A relayer that
wants its own evidence runs `zk_fri_rank_check(proof, publics)` on the bytes it was handed.
