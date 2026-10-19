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
   prints as `DepositKey(redacted)` and never crosses the FFI.
2. The blinding of deposit index i is four field words drawn under the context `shield/deposit/v1`
   from the deposit key, the chain id (8 bytes, little endian), the pool address (20 bytes), the
   account index (4 bytes, little endian) and i (4 bytes, little endian). The draw is the field key
   draw the spend secret uses: 128 bytes of BLAKE3 output through the rejection sampler of the
   prover, so every word is below p and no two indices share a commitment by reduction.
3. The index is counted per account. The first free index is one past the highest index any kept
   deposit used, read from a new row of the sealed note log of the account, `DepositIndex`, kind 5
   (`store/row/mod.rs`). The row is written before the deposit row, and both before the transaction
   leaves, so a crash between them wastes an index and never reuses one.
4. A review draws its indices without writing them. A single deposit review passes over the indices
   a held split review has drawn, and a split review passes over the index a held single review has
   drawn, so the two reviews that can be alive at once never carry the same blinding
   (`ffi/wallet/deposit_held.rs`). The index is written when the owner confirms. A deposit made for
   another wallet (`prepare_deposit`) writes it at once, since its note is kept at once.

The other secret a deposit note carries is its spend key, which is the public `spend_pk` of the
account. Value and asset are public. The blinding is the only secret, and it is now a function of
the words.

## Finding deposits again

At every sync, and for each account the account search reaches after a restore
(`ffi/wallet/find_steps.rs`), the core runs `discovery::recover_deposits` over the leaves it has
already read:

1. For each index from the first free one, it draws the blinding and computes the owner digest
   `compress(spend_pk, blinding)` once.
2. For each value a deposit can hold, it computes the commitment `compress(public, owner)` and looks
   it up among the `NoteCommitted` leaves. A deposit is a standard size of a pool asset, 1, 2 or 5
   followed by zeros inside the range of the pool, less the deposit fee rounded down, so the set is
   public and small: 10 ETH sizes and 12 NOX sizes on the production pool, each at every fee from 0
   to 100 basis points (`MOST_DEPOSIT_FEE_BPS`), 2,222 values in all.
3. A match is a deposit of this account. It is recorded as a held note with its leaf, after a
   `DepositIndex` row for the highest index found, so the next deposit draws past it.
4. The nullifier of every note found in this sync is checked against the `NullifierSpent` history
   at once, so a deposit spent before the restore shows as spent after the first sync. The same
   check now covers received notes found in the same sync, which before waited for a second sync.

The search stops after `DEPOSIT_GAP` indices in a row find nothing.

## The gap limit

`DEPOSIT_GAP` is 24 (`discovery/deposits.rs`), in the spirit of the 20 empty addresses of BIP-44.
An index leaves no leaf in two ways.

A review drawn and never confirmed writes nothing, so its indices are drawn again later, unless a
deposit confirmed meanwhile has moved past them. The most that can be passed over this way is what
the reviews alive at once hold: one split of up to 20 deposits and one single deposit, 21 indices,
which the gap passes (a test pins `DEPOSIT_GAP > MAX_PIECES + 1`). The rest of a split that stops
at its first failed send was never written either.

A confirmed deposit whose send fails has written its index, and that index stays empty. Nothing
bounds a run of those. A deposit that follows more than 24 failed sends in a row is not found by a
restore, though the device that made it still holds it. Raising the constant costs one more index
of hashing per sync and needs no change to any stored format.

## Cost

Per index tried: one BLAKE3 draw and 2,223 Poseidon compressions, one for the owner digest and one
per value. A sync of an account with nothing new tries 24 indices, 53,352 compressions. A restore
tries the indices up to its last deposit plus 24. The account search after a restore tries at
least five accounts this way, so it hashes at least five times that. Only the unoptimised test
build has been timed: there a Poseidon compression took 112 µs on a 4-core server, 10,000 in
1.12 s, so one idle sync of one account is about 6 s of hashing in that build. An optimised build
is many times faster, and neither a release nor a phone figure has been measured. The number to
take before a release is the time of one idle sync per account on the slowest supported phone.

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
to anyone without the deposit key, as a random one was. Two deposits of one account have unrelated
blindings, since each index is a separate draw.

What changes is who can find the deposits. Anyone with the words could already spend everything the
wallet holds. They can now also find the deposits, which is the purpose. The deposit key, if it
leaked from memory without the rest, would let its holder recognise the deposits of the account
among the leaves, as a copy of the note store with its key would. It is never written, exported or
shown.

## Compatibility

Notes made before this change keep their random blinding. They stay in the store as deposit and
found rows and are matched as before: a pending deposit is recognised from its stored plaintext,
and a held note spends as any other. They are not found by a restore from the words, as before. A
test pins that such a note is still found from its store and spends (`ffi/wallet/sync_each_test.rs`).

The first deterministic deposit of an existing wallet is index 0, since an older store holds no
`DepositIndex` row. No old deposit used an index, so nothing repeats.

The vault is unchanged. The note log gains one row kind, which older stores do not contain, so every
existing store reads as before. A store written by this build and then opened by an older build is
refused at the first `DepositIndex` row as a store from a newer version, as the store refuses every
unknown kind. Downgrading the app after a deposit therefore needs a restore from the words.

The derivation is new and touches no other key: account vectors, view keys, addresses and the
public accounts are byte for byte as before (`keys/accounts_vectors.rs` passes unchanged).

## The iOS and Android shells

No exported function, record or enum changed, so the generated bindings and the shells are the
same. What changes is behaviour behind the same calls:

- `prepare_deposit`, `review_shield` with `confirm_public_send`, and `review_shield_split` with
  `confirm_shield_split` make notes with derived blindings.
- `sync_chain` also reports recovered deposits in `deposited`, and may report more in `spent` on the
  first sync after a restore.
- `find_accounts` counts an account whose only use is a deposit, for example one made from an outside
  wallet.

## What it changes in the native library

New files: `keys/deposit_key.rs`, `keys/deposit_site.rs`, `discovery/deposits.rs`,
`discovery/deposit_values.rs`, `wallet/deposit_recover.rs`, `wallet/session/deposit_draw.rs`,
`ffi/wallet/deposit_held.rs` and `ffi/wallet/deposit_site.rs`. Changed: the account holds a deposit
key, the store folds the new row, `prepare_deposit_at` takes the blinding, and the deposit reviews,
confirmations and the per-account sync use them. No new dependency: the derivation is the BLAKE3
key derivation and the rejection sampler the core already uses.

## Vectors

For the phrase "abandon" eleven times then "about", chain 11155111 and the production pool
`0xaEe51E82965Ec1DeD870F3f4c248Ad4AdDc3e1cb`, pinned in `keys/deposit_key_test.rs`. Each blinding
is its four words in order, each as sixteen hex digits.

| Account | Deposit | Blinding |
|---|---|---|
| 0 | 0 | `63c512c68338b9ce6a502bf3ba4e5a2df46bd28e8a7e4196d896c55b3f5ba88d` |
| 0 | 1 | `50d705c61ab2c3e65e5acb0829c5d16b659e601ad27f2a2d41f93e57d3702174` |
| 1 | 0 | `b4091403d3a5bdf3dbeddc599f4716e932a9f64c4b5cb343af201ed975a98568` |
| 1 | 1 | `e3a040c1855a76b0e1fa76140f8e24deb299aa818880947e6ac3f04815f51f8c` |

## Open points

Two devices restored from the same words and depositing at the same time draw the same indices. A
second deposit of the same amount at the same index would have the same commitment as the first. A
sync on either device moves its index past the other device's deposits once they are on chain, so
the window is the time between the two deposits and the next sync.

A view key does not carry the deposit key, so a view-only account still sees received notes and no
deposits, as before.
