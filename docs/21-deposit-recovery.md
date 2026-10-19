# Deposit recovery

How a wallet restored from its recovery words finds its unspent deposits again, what that reads,
what it costs, and what it changes. What is checked and what is not is in
[20-security-status.md](20-security-status.md).

## The problem

A note received from another wallet travels with an X-Wing sealed blob in an `OutputNote` event, so
a restore opens it with the receiving key and finds it. A deposit has no such blob: the depositor
holds the opening. Until this change the opening of a deposit was a random blinding
(`notes::fresh_blinding`) kept only in the note store of the device that made it, and the scan
recognised an own deposit only by matching that stored plaintext against the leaves of the pool. A
restore from the words on another device, or after the app storage was lost, found every received
note and no deposit.

## The design

Each deposit blinding is now drawn from the seed.

1. Every account derives a deposit key, 32 bytes, from its key material under the BLAKE3 context
   `nox-shield 2026 deposit key v1`, as it derives its view key and its store key
   (`keys/deposit_key.rs`). It lives in the account while the wallet is unlocked, wipes on drop,
   prints as `DepositKey(redacted)` and never crosses the FFI. A copy, which a search running
   without the session lock holds, wipes on drop the same way.
2. The blinding of deposit index i is four field words drawn under the context
   `nox-shield 2026 deposit blinding v1` from the deposit key, the chain id (8 bytes, little
   endian), the pool address (20 bytes), the account index (4 bytes, little endian) and i (4 bytes,
   little endian). The draw is the field key draw the spend secret uses: 128 bytes of BLAKE3 output
   through the rejection sampler of the prover, so every word is below p and no two indices share a
   commitment by reduction.
3. The indices used are kept per account in the sealed note log of the account, as a row of kind 5,
   `DepositIndex` (`store/row/mod.rs`). The row is written before the deposit row, and both before
   the transaction leaves, so a crash between them wastes an index and never reuses one.
4. A draw takes the lowest indices that are neither used nor reserved, and reserves them, in one
   step under the session lock (`wallet/session/deposit_draw.rs`). A reservation lasts five minutes
   or until the review holding it is replaced, whichever comes first (`ffi/wallet/deposit_held.rs`).
   So two reviews alive at once on one device do not hold the same index, whichever threads they
   run on. If a reservation runs out under a review slower than five minutes and its index is drawn
   again, the second yes for that index is refused, as the next point says.
5. A review's index is written when the owner confirms, and Tor is reached first, so a confirm that
   cannot reach the network writes nothing. The confirm is refused as expired when a deposit kept or
   found since the review has taken its index, for example when a sync has found the deposit of
   another device on the same words at that index.
6. `prepare_deposit` returns the transactions for a deposit from the user's own outside wallet into
   this wallet. Its note must be kept before the ticket is shown, so it draws and keeps its index in
   one step under the session lock.

The other secret a deposit note carries is its spend key, which is the public `spend_pk` of the
account. Value and asset are public. The blinding is the only secret, and it is now a function of
the words.

## Finding deposits again

At every sync, and for each account the account search reaches after a restore
(`ffi/wallet/find_steps.rs`), the core searches the leaves it has already read
(`discovery/deposits.rs`, `ffi/wallet/deposit_search.rs`):

1. What the search needs, a copy of the deposit key and the spend key, is taken from the session in
   one short call. The hashing then runs without the session lock.
2. For each index from 0, it draws the blinding and computes the owner digest
   `compress(spend_pk, blinding)` once.
3. For each value a deposit can hold, it computes the commitment `compress(public, owner)`. A
   deposit is a standard size of a pool asset, 1, 2 or 5 followed by zeros inside the range of the
   pool, less the deposit fee rounded down, so the set is public and small: 10 ETH sizes and 12 NOX
   sizes on the production pool, each at every fee from 0 to 100 basis points
   (`MOST_DEPOSIT_FEE_BPS`), 2,222 values in all. A deposit at a higher fee would never be found,
   so the core refuses one before review, although the contract would take it
   (`wallet/deposit_gate.rs`).
4. The first four bytes of each commitment are kept per account until the wallet locks, so a later
   sync hashes only the indices past those already kept. The pool's leaves are read once per sync
   for every account, and each sync compares the kept prefixes against them. A prefix that matches
   is checked against the whole commitment before it counts.
5. A match is a deposit of this account. Every leaf holding that commitment is a deposit of its own.
   Each is recorded as a held note at its leaf, after a `DepositIndex` row for each index found that
   was not yet used, so no later draw takes it and a review that drew it before the sync is refused
   at its yes.
6. The nullifier of every note found in this sync is checked against the `NullifierSpent` history
   at once, so a deposit spent before the restore shows as spent after the first sync. The same
   check now covers received notes found in the same sync, which before waited for a second sync.

The search starts at index 0 every time, because a hole below the highest index used can be filled
later, by this device or by another one on the same words. It stops after `DEPOSIT_GAP` indices in
a row find nothing.

## Notes keyed by commitment and leaf

Two deposits of one amount drawn at one index have the same commitment. That happens when two
devices on the same words each deposit at an index neither has seen used, and when an index is
taken again as the next section describes. The pool stores each at its own leaf, and each is a note
with its own nullifier, since the nullifier hashes the leaf.

The store therefore keeps notes by commitment and leaf (`store/state.rs`). A status row now names
the leaf as well, in a new row kind, 6. A status row of the older kind 2 names only a commitment and
still reads, for every note held under it, which is what it meant when one commitment was one note.

## The gap limit

`DEPOSIT_GAP` is 64 (`discovery/deposits.rs`), in the spirit of the 20 empty addresses of BIP-44. A
run of indices with no leaf has three sources:

- Indices reserved by reviews not yet confirmed. At most one split of up to 20 deposits and one
  single deposit are held at once, 21 indices, and an abandoned review frees its indices when it is
  replaced or after five minutes, after which a draw takes them again.
- Indices kept for a deposit that never lands: a ticket from `prepare_deposit` never paid, or a
  confirmed deposit whose send failed. Each writes its index, and the index stays empty.
- Indices kept for deposits sent and not yet seen by a sync, up to 20 for a split.

The second source used to be unbounded: 24 unpaid tickets in a row, with the old gap of 24, hid every
later deposit from a restore. A kept index now counts as seen once a held note carries its blinding.
Once `MOST_UNSEEN`, 8, kept indices are not seen, a draw takes the lowest of them again instead of a
new index (`wallet/session/deposit_draw.rs`). The empty run therefore stays near 21 reserved plus 8
unseen plus 20 in flight, and a test pins `DEPOSIT_GAP` above twice 21 plus 8. A test also makes
72 unpaid tickets and then a deposit that lands, and a restore finds it.

Taking an index again has a cost. If the earlier ticket is paid after all, both deposits at that
index land, both are found, and both are spendable, but they carry the same owner digest on chain,
so an observer can tell they belong together. With the same amount they also carry the same
commitment. A device that does not sync counts its landed deposits as unseen too, so after 8
deposits without a sync it takes indices again with the same cost.

Raising `DEPOSIT_GAP` costs one more index of hashing at the first sync of each account after an
unlock, and nothing at later syncs. It needs no change to any stored format.

## Cost

Per index: one BLAKE3 draw and 2,223 Poseidon compressions, one for the owner digest and one per
value. Measured with `time_the_deposit_search` in `discovery/deposits_test.rs`, built in release
on a 4-core Intel Xeon at 2.10 GHz that was running other builds at the same time (load near 5):

| | Time |
|---|---|
| One index hashed | 13.4 ms to 15.3 ms |
| First sync of an account with no deposits, 64 indices | 0.86 s to 0.98 s |
| A later sync from the kept candidates, against 10,000 leaves | 1.1 ms to 1.3 ms |
| Reading 10,000 leaves once per sync | 2.5 ms to 3.1 ms |

The kept candidates take 4 bytes per value per index, about 570 KB for an account searched to
index 64. The account search after a restore searches at least five accounts, so about 5 s of
hashing at these rates, outside the session lock. No phone has been measured. The number to take
before a release is the first sync of one account on the slowest supported phone.

## What an observer learns

Nothing new is read. The search runs on the `NoteCommitted` leaves and the `NullifierSpent`
history that every sync already fetches, from the pool address and the event topic alone
(`wallet/sync_chain.rs`). It sends no request, so neither an RPC nor the network path can tell a
wallet that recovers from one that does not.

The candidate amounts are not read from the chain either. Reading each deposit amount from the
transactions of the depositor would ask an RPC about one EVM address and so link it to the pool
interest of this wallet, an ETH deposit leaves its amount in no log at all, and a deposit made from
an outside wallet has a depositor the seed does not derive. Trying every value a deposit can hold
avoids all three.

On chain a deposit looks as it did. The calldata of `absorb` carries the owner digest, which is a
Poseidon compression of the spend key and the blinding and shows neither. The blinding is uniform
to anyone without the deposit key, as a random one was. Two deposits of one account at different
indices have unrelated blindings, since each index is a separate draw. Two at one index do not, as
the gap limit section says.

What changes is who can find the deposits. Anyone with the words could already spend everything the
wallet holds. They can now also find the deposits, which is the purpose. The deposit key, if it
leaked from memory without the rest, would let its holder recognise the deposits of the account
among the leaves, as a copy of the note store with its key would. The kept candidate prefixes would
let their holder pick out likely deposits of the account the same way. Neither is written,
exported or shown, and both are dropped when the wallet locks.

## Compatibility

Notes made before this change keep their random blinding. They stay in the store as deposit and
found rows and are matched as before: a pending deposit is recognised from its stored plaintext,
and a held note is offered for spending as any other. They are not found by a restore from the
words, as before. A test pins that such a note is still found from its store and held as spendable
with its stored blinding (`ffi/wallet/sync_each_test.rs`). No test makes a proof spending it.

The first deterministic deposit of an existing wallet is index 0, since an older store holds no
`DepositIndex` row. No old deposit used an index, so nothing repeats.

The vault is unchanged. The note log gains two row kinds, 5 and 6, which older stores do not
contain, so every existing store reads as before, its status rows included. A store written by this
build and then opened by an older build is refused at the first row of either kind as a store from
a newer version, as the store refuses every unknown kind. Downgrading the app after a deposit, a
spend or a sync that marks a note spent therefore needs a restore from the words.

The derivation is new and touches no other key: account vectors, view keys, addresses and the
public accounts are byte for byte as before (`keys/accounts_vectors.rs` passes unchanged).

## The iOS and Android shells

No exported function, record or enum changed, so the generated bindings and the shells are the
same. What changes is behaviour behind the same calls:

- `prepare_deposit`, `review_shield` with `confirm_public_send`, and `review_shield_split` with
  `confirm_shield_split` make notes with derived blindings.
- `confirm_public_send` can answer that the review expired when a sync since the review found a
  deposit at its index, and `confirm_shield_split` then stops at that deposit, with the ones before
  it sent and the reason in `stopped`, or answers expired when it is the first. The shell reviews
  again, as for any expired review.
- A pool fee above 100 basis points is refused with its own sentence before review.
- `sync_chain` also reports recovered deposits in `deposited`, and may report more in `spent` on the
  first sync after a restore.
- `find_accounts` counts an account whose only use is a deposit, for example one made from an outside
  wallet.

## What it changes in the native library

New files: `keys/deposit_key.rs`, `keys/deposit_site.rs`, `discovery/deposits.rs`,
`discovery/deposit_values.rs`, `wallet/session/deposit_draw.rs`, `ffi/wallet/deposit_held.rs`,
`ffi/wallet/deposit_search.rs` and `ffi/wallet/deposit_site.rs`. Changed: the account holds a
deposit key, the store keeps notes by commitment and leaf and folds the two new rows,
`prepare_deposit_at` takes the blinding, the deposit gate refuses a fee above the search, and the
deposit reviews, confirmations, the sync and the account search use them. No new dependency: the
derivation is the BLAKE3 key derivation and the rejection sampler the core already uses.

## Vectors

For the phrase "abandon" eleven times then "about", chain 11155111 and the production pool
`0xaEe51E82965Ec1DeD870F3f4c248Ad4AdDc3e1cb`, pinned in `keys/deposit_key_test.rs`. Each blinding
is its four words in order, each as sixteen hex digits.

| Account | Deposit | Blinding |
|---|---|---|
| 0 | 0 | `2b6ef0e0903b933420d63051a8671a53569e9499c929bcd5b625ef8a24ab5391` |
| 0 | 1 | `7f872a867f5db5c190d8244e99478c610be08bb3c45e6ff40949d62d9be4f6a2` |
| 1 | 0 | `ff694c64e5fd1ba09c340298d222df14d5e532216d28f11173b82fc7fd2147ff` |
| 1 | 1 | `ea29e76a619c578156ecda48f09aeb8eb87daff775f0067149a25bd9850edcbb` |

## Open points

Two devices on the same words can draw the same index when neither has synced the other's deposit.
Both deposits land and both are found and spendable, as the section on notes keyed by commitment
and leaf says, but they show the same owner digest on chain. A review is refused at its yes only
when its device has already synced the other deposit.

A view key does not carry the deposit key, so a view-only account still sees received notes and no
deposits, as before.
