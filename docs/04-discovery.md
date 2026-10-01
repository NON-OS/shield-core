# Discovery

How the wallet finds which notes in the pool are its own without telling anyone which it is looking
for, what that costs, and the two alternatives with the reasons they are not used. What is checked
and what is not is in [20-security-status.md](20-security-status.md).

## What the pool publishes

Four events, all from the pool contract, read by `wallet::sync_chain::fetch_history`:

| Event | What it carries |
|---|---|
| `NoteCommitted(bytes32 commitment, uint40 leafIndex)` | every leaf of the note tree |
| `OutputNote(uint40 leafIndex, bytes clientData)` | the sealed note for each settlement output. A deposit has none, since its depositor holds the opening |
| `NullifierSpent(bytes32 nullifier)` | a spent note |
| `RootCommitted(bytes32 root, uint40 leafCount)` | each root a spend can anchor to |

The same `NullifierSpent` history tells a published spend that it landed: `follow_spend` looks for
both of its nullifiers in it (`core/src/wallet/publish/landed.rs`), so watching a spend asks no
server about it.

Every sealed note is 1,186 bytes (`notes::xwing::BLOB_LEN`):

| Bytes | Field |
|---|---|
| 0 | version, `0x01` |
| 1 | view tag, the first byte of SHA3-256 of a label and the shared secret |
| 2 to 1,121 | X-Wing ciphertext: ML-KEM-768, then X25519 |
| 1,122 to 1,185 | ChaCha20-Poly1305 of the 48-byte opening, with the leaf commitment as associated data |

Every note has the same length, so the events say how many outputs there are and nothing about who
they are for.

## What the wallet does: a full scan

The wallet reads all four events from the deploy block of the pool to the head, in windows of 10,000
blocks, over its own Tor on circuits kept for the scan. The request is the pool address and the event
topic and nothing else, so every wallet sends the same requests, and an RPC learns that someone read
the pool, never which notes they wanted.

The history is accepted only whole. The leaves must be `0` to `nextLeafIndex - 1`, read at the same
block. `discovery::first_gap` finds a hole in the middle, and a count short of `nextLeafIndex` is a
missing tail. A server that serves either is refused and the next one is tried, because a wallet that
trusted a short history would show a balance with notes missing.

Then `discovery::scan_chain` tries every `OutputNote`: an X-Wing decapsulation, the view tag compared,
and on a match the authenticated open and the checks of the plaintext. The last check is one no pool
can pass for a note belonging to another wallet: the opening must recompute to the leaf the pool
emitted. Deposits this wallet sent are matched to their leaves by commitment, and a published
nullifier marks a held note spent.

## The cost

| What | Per output note |
|---|---|
| Bytes read | 1,186 of note, plus the event framing of the RPC |
| Work | one X-Wing decapsulation, and an authenticated open on the 1 in 256 whose tag matches |

A settlement adds two output notes, so the pool grows by 2,372 bytes of notes per private transfer.
The work per note on a phone is not measured. The numbers to take are in the last section.

## Alternative: a filtered scan

The wallet could send something that narrows the set, a view tag or a Bloom filter, and receive only
matching notes. Bandwidth falls by the selectivity of the filter, and the server learns the filter. A
one-byte view tag makes every note it returns 256 times more likely to belong to this wallet than a
random one, and over a few sessions that is an account linked to a Tor exit and a time pattern. Not
used. The view tag here is computed by the wallet from a shared secret and never sent. It is a local
shortcut past the authenticated open, the opposite of this option.

## Alternative: private information retrieval

The wallet could fetch the matching notes without the server learning which. Bandwidth falls toward
the matching set plus the overhead of the scheme. The cost moves to computation on both sides, and to
assumptions the scheme must hold. Not used. It becomes worth the complexity when the size of the pool
makes the full scan expensive on a phone, and the decision comes with both measured.

## What has to be measured on a phone

| Number | How |
|---|---|
| X-Wing decapsulations per second | `scan_chain` timed over a known number of notes |
| Notes scanned per second, end to end | wall clock over a whole history read |
| The view tag hit rate | tag matches over notes, which should land near 1 in 256. `scan_chain` does not count them |
| The energy of a full scan | a scan of a known count, measured on the device |

A full scan that costs more battery than a person accepts is what would force the second
alternative, and that is a number, not a preference.
