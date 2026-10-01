# Architecture

One Rust core, two thin apps, and one boundary between them. This page is for a reader who
wants to know which part decides what before reading the code. What is checked and what is not is
in [20-security-status.md](20-security-status.md).

## The shape

```
Kotlin, Compose                    Swift, SwiftUI
      |                                  |
      +--------------+   +---------------+
                     |   |
                 UniFFI boundary
                        |
   +--------------------+---------------------+
   |              nox_shield_core             |
   |                                          |
   |  wallet     shield flows: sync, spend,   |
   |             deposit, publish, follow,    |
   |             take back, rewards link      |
   |  evm        public account: balances,    |
   |             review, send, swap           |
   |  prover     launch proof, rank check     |
   |  notes      X-Wing sealed notes          |
   |  store      sealed append only note log  |
   |  discovery  trial decryption of outputs  |
   |  keys       shield keys, address codec   |
   |  custody    phrase, seed, seal, guard    |
   |  net        embedded Tor, TLS, JSON-RPC  |
   +-----+------------------+-----------------+
         |                  |
   vendor/: nonos-stark,   nonos_hd, nonos_seal
   stark_proofs,           (BIP-39, BIP-32,
   nox_prover              ChaCha20-Poly1305)
```

The apps own the window, the platform keystore and the screens. Everything
that decides anything sits below the boundary: what an address means, what an
amount parses to, which notes a spend uses, what a send or a swap will do, and
which network a request may reach.

## What crosses the boundary

Records of plain numbers and strings, amounts already formatted as text, and
three objects: the wallet, a cancellation token, and the hardware guard. The
guard is the only trait that goes the other way. Each platform implements it
with its keystore, and it wraps and unwraps a 32-byte file key without ever
seeing a seed.

No seed, no key, no note plaintext and no proof bytes cross the boundary. A
proof leaves the core only through the core: published for anyone to land, or
settled by the owner from the public account, or as files the core wrote.

## The calls of the production pool

What a screen calls for the flows of the production pool, each a method of the wallet:

| Call | What it returns |
|---|---|
| `quote_spend(coin, amount, withdraw)` | the network fee, the protocol fee, the total, the rung and the base fee, or why the policy would refuse it |
| `send_private`, `withdraw` | the hand-off of a spend, refused with `FeeChanged` when its fee moved after the quote |
| `publish_spend()` | where the spend proved last was published, and the id the lander gave it |
| `follow_spend()` | waiting, republished, landed with its transaction and link, or spent elsewhere, and whether a self settlement is offered |
| `review_self_settle()` | the settlement of that spend from the public account, refused for 30 minutes after a publication |
| `review_shield_split(coin, amount)`, `confirm_shield_split(id)` | the standard deposits of one amount under one review, then the deposits sent in order |
| `rewards_link()`, `rewards_message(mainnet)` | the link of the active account, and the typed data another wallet signs |
| `review_rewards_link(mainnet, signature)`, `review_rewards_link_own(account)`, `review_rewards_unlink()` | a link or an unlink held for `confirm_public_send` |

`hand_to_relayer` and `relayer_state` remain, and a hand-off made through them starts the same
timers as `publish_spend`.

For the prover team, `profile_proof(threads, cancel)` proves the pinned 37-limb `transfer-eth`
vector from the periodic cache in the wallet folder, on every core when `threads` is 0 or on a
pool of that many threads, and returns the time of each of the eleven phases the prover reports,
the time after Verified, the total, the threads it ran on, and whether the proof is the pinned
`proof.json` byte for byte. It needs no unlocked account, since the vector brings its own fixture
notes. Peak memory is not in it: each app reads its own (`core/src/bench/profile`).

## The long calls

Proving, scanning the pool, reading the public account, and working out a send
or a swap. All of them run off the main thread in both apps. Proving carries a
cancellation token that the core checks between stages, so a cancelled proof
is dropped between stages and never killed mid allocation.

## Custody

The phrase is BIP-39 with no passphrase: 24 words when the wallet makes it, 12 to 24 when the
owner brings one. The seed it derives, and from version 2 of the vault the word indices, are
sealed on the device under ChaCha20-Poly1305 with a file key that the platform
keystore wraps: StrongBox or the TEE on Android, a Secure Enclave P-256 key on
iOS. The keystore key opens only when the owner is present.

Two families of keys descend from the seed, and neither is derived from the
other:

- The shield keys, through BLAKE3 in derive-key mode, one context per
  purpose: `nox-shield 2026 spend key v1`, `view key v1`, `receive key v1` and
  `note store key v1`. The receive key is an X-Wing key, X25519 with
  ML-KEM-768.
- The public account, through BIP-32 at `m/44'/60'/0'/0/0`, the path every
  Ethereum wallet uses, so the same words give the same `0x` address in any of
  them. `core/src/evm/account_test.rs` checks it against the BIP-39 test phrase.

## Notes

A note a payee receives is 1,186 bytes, version `0x01`: a view tag, an X-Wing
ciphertext, and a ChaCha20-Poly1305 seal of the 48-byte opening whose
associated data is the leaf commitment. A note opens only beside the leaf it
was written for, and the opening must recompute to that leaf before the wallet
counts it. `core/src/notes/xwing.rs` has the layout, and `xwing_test.rs` holds the
pinned vector.

## The store

An append only log of sealed rows under a key derived from the seed. Rows are
found notes, status changes, deposits waiting to be stored, and the scan
cursor. The balance of each asset is what those rows fold up to. Nothing is
rewritten, so a power cut costs the last row and leaves the store, and a row
that does not authenticate stops the replay.

## A shielded spend

`core/src/wallet/spend/flow.rs`, in order:

1. Quote the fee before anything else (`core/src/net/fee_quote.rs`): the protocol part, flat on a
   private transfer and 0.50% of a withdrawal, and the lowest rung of the gas ladder of the policy. The policy is asked with `settlementFee` whether it takes that fee. A
   screen shows the two parts apart (`quote_spend`), and a spend whose fee has moved since the quote
   is refused with `FeeChanged` and quoted again, so the fee proved is a fee the owner saw.
2. Read the whole history of the pool over Tor and anchor to the newest committed root that the
   association registry holds (`wallet/registry.rs`).
3. Pick one note and a dummy, or the two largest notes, of the asset spent, from the notes past the
   wait: 20 more leaves and 1,800 blocks, about 6 hours, after each was committed. The owner can
   skip the wait by typing EARLY (`wallet/spend/ripe.rs`).
4. Build the request and check it against the rules of the pool before any proving time is spent:
   standard sizes, the fee under its cap, thirteen public words. The thirteenth is the not-before
   time, the ten-minute grid point just passed (`wallet/spend/not_before.rs`), so every spend proved
   in one slot carries the same time.
5. Prove with the production prover, then run the zero-knowledge rank check on the proof. A proof
   that fails the check is proved again with fresh entropy, up to 3 attempts.
6. Seal the two outputs, one to the payee and the change to this wallet, and write the hand-off:
   the proof, its 37 public limbs and the two sealed notes. Mark the spent notes pending.

## Open settlement

Every proof pays its fee to `address(1)`, which the pool credits to whoever submits the
settlement, so anyone may land it and the wallet holds no lander address.
`core/src/wallet/publish` and `core/src/ffi/wallet/publish.rs`:

1. `publish_spend` hands the spend over through Tor, never direct, and writes a record of when,
   beside the hand-off, so its timers outlast a restart. The route today is the lander onion. The
   public Waku topic goes first once its publish specification is in this repository.
2. `follow_spend` reads the whole history of the pool, as every scan does, and looks for both
   nullifiers of the spend. Both in one transaction is a landing, with that transaction. One or both
   elsewhere means another proof spent a note, and the screen says so.
3. A spend that has not landed 15 minutes after its latest publication is published again.
4. Thirty minutes after its first publication, the owner is offered to settle it from the public
   account (`review_self_settle`), which names that account in public beside the spend. Before
   then the offer is refused while a lander is on.

If nothing lands at all, take back reads the history again and returns every pending note the
chain shows unspent.

## A deposit

A deposit is a public `absorb` from the public account or from the wallet of the owner, of a
standard size: 1, 2 or 5 followed by zeros, inside the range of the pool. The pool keeps 0.50%
(`depositFee` of the policy) and the note holds the rest. One typed amount that is not a standard
size becomes the fewest standard deposits under one review (`core/src/wallet/deposit_split.rs`,
`review_shield_split`): 0.37 ETH is 0.2, 0.1, 0.05 and 0.02. They go out on consecutive nonces
after one confirmation, each note stored before its deposit leaves, and the first that fails stops
the rest (`confirm_shield_split`). For NOX, the exact approval of the whole amount comes first.

## The rewards link

The registry on Sepolia, `0xf1DC54d83b21D416ce619fA8C2E29C8381594225`, links a mainnet address
that holds or locks NOX to one testnet address, so the testnet rewards count its stake.
`core/src/wallet/rewards`:

- The mainnet address signs `Link(address mainnet,address testnet,uint256 nonce)` under the domain
  `NOX testnet rewards`, version 1, chain id 1. An account of this wallet signs here
  (`review_rewards_link_own`). Another wallet signs the typed data `rewards_message` returns, and
  its signature is checked here against the mainnet address before review, or, for a contract
  wallet, by ERC-1271 on mainnet.
- The active account sends `link` on Sepolia, reviewed and confirmed like a deposit. A link the
  registry would refuse is refused first: a testnet address linked elsewhere, a change already made
  this epoch, or the link already in force, which a second send would delay by an epoch.
- A link or an unlink counts from the next weekly epoch. Epoch 0 began on 1 October 2026.

## A public send or swap

`core/src/evm`. A review reads, in batches that open with `eth_chainId`: the
balance, the pending nonce, the latest block, the suggested tip, whether the
recipient has code, a gas estimate as the sender, and for NOX or a swap the
token and pool state from two servers that must agree. It returns either a
refusal in one sentence or a transaction and what it will do. The transaction
is held for 90 s under an id, bound to the account it was made for. Confirming
asks the platform for the owner, checks the chain id once more, signs with the
chain id of the selected network, and sends. On mainnet the send goes to a
private relay.

## What is proved, and by what

| Layer | Tool | Where |
|---|---|---|
| Amount arithmetic, transfer balance, address alphabet, the fee, offer, nonce and cover of a public send, on the Rust that ships | Lean 4 through Charon and Aeneas | `verified/`, `lean-verified/` |
| The store, conservation, the blinding seed, discovery, wipe, on models | Lean 4 | `lean/` |
| No panic or overflow in the fee offer, gas limit, RLP, NOX fee split, revert decoding, balance check | Kani | the `*_kani.rs` files in `core/src/evm` |
| Nonces, reviews, notes across two devices, take back | TLA+ | `spec/` |
| The production prover proves the four pinned 37-limb vectors byte for byte, and the production verifier accepts them | `core/tests/prod_vectors.rs`, and `verifyBatch` read with `eth_call` | by hand, 1 October |
| The launch verifier accepts proofs from the launch prover | the verification kit | `ci/verify-kit`, CI job `launch-proof` |

## Where the numbers come from

`README.md` and [20-security-status.md](20-security-status.md). A number in this repository is
quoted with how and where it was measured, or it is not quoted.
