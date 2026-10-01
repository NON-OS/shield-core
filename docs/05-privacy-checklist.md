# Privacy checklist

The proof hides a transfer, and the app can still leak it unless every rule on this list holds. Each
line names the code or the check that keeps the rule. What each observer learns is in
[02-threat-model.md](02-threat-model.md), every leak with its bound is in
[06-leak-ledger.md](06-leak-ledger.md), and what is checked and what is not is in
[20-security-status.md](20-security-status.md).

| Rule | Where it is kept |
|---|---|
| No analytics, no crash reporter, no attribution SDK, no advertising identifier | The code of the core writes to no log and no terminal (`scripts/check-no-logging.sh`). The vendored `nonos-stark` writes ten lines of its own resident memory to standard error while it builds the periodic tree, on the first proof of a device, and nothing else was printed in the profile runs of 1 October. They name no value of a spend, and a feature that leaves them out is asked of the prover team. The core generates no identifier (`scripts/check-no-identifiers.sh`), and links only the 507 crates in `scripts/dependencies.allow`, which CI recomputes on every push. The Android app links the binding layer and ZXing, and its `scripts/check-package.sh` reads the built package. The iOS app links nothing beyond the core |
| Every request over Tor, with no direct mode | `core/src/net/tor`, embedded in the core, with isolated circuits per purpose. `scripts/check-one-destination.sh` refuses a socket API or a URL outside `core/src/net` |
| The shielded balance never asks a server about an address | the pool history is read whole, with the same requests from every wallet, and notes are found by trial decryption on the device: `core/src/wallet/sync_chain.rs`, `core/src/discovery` |
| No request that names a note | same |
| Nothing signed that the owner did not see | a public send, a swap, a deposit, a split deposit, a rewards link and a self settlement are each worked out in full by the core, shown, held for 90 s under an id bound to the account, and signed only after the platform confirms the owner: Face ID, Touch ID or the passcode on iOS, a strong biometric or the device credential on Android |
| No fee that names the wallet, and none the owner did not see | the fee of a spend comes from the policy of the pool, the protocol part and the lowest rung, the same for every wallet, and nothing about it is typed. It is shown as a network part and a protocol part before proving, and a spend whose fee moved since is refused and quoted again: `core/src/net/fee_quote.rs`, `core/src/ffi/wallet/quote.rs` |
| A proof leaves only through Tor, for anyone to land | `publish_spend` and `follow_spend` in `core/src/ffi/wallet`, over the relay circuits. Landing is watched in the whole pool history, never by asking about a nullifier |
| No transaction signed for the wrong network | every batch opens with `eth_chainId`, the chain id is checked again before signing, and it is inside the signature: `core/src/evm/rpc.rs`, `send.rs`, `tx.rs` |
| No screenshots of balance screens | Android sets `FLAG_SECURE` before the first frame. iOS covers its window off the foreground and while the screen is recorded, mirrored or shared. iOS has no way to block a screenshot the owner takes, and answers a screenshot of the recovery words with a warning to delete it |
| No amounts in notifications | neither app posts a notification, and neither declares a notification permission |
| No address in the clipboard longer than a paste | a copied address or hash is cleared after 60 s. Android marks it sensitive, so keyboards and clipboard previews do not show it. iOS keeps it local to the device |
| No permission beyond what is used | Android declares `INTERNET`, `USE_BIOMETRIC`, and `USE_FINGERPRINT` on API 28 only. Its `scripts/check-manifest.sh` reads the merged manifest |
| No cloud backup of the seal | Android excludes the whole data directory from backup and device transfer. iOS marks its container excluded and declares no iCloud entitlement, keychain sharing or app group |
| Local storage encrypted | the vault is ChaCha20-Poly1305 under a keystore-wrapped key. The note log seals every row under a key derived from the seed |
| Assume the phone is seized unlocked | locking drops the session and every derived key. Unlocking asks the keystore, which requires the owner. Each public send asks again |
| Reproducible builds, published | [07-reproduce.md](07-reproduce.md) here, `docs/03-reproduce.md` in each app repository, and the Android `reproduce` workflow, which builds one commit twice and compares the packages by hash |
| Proof randomness from the platform CSPRNG, fresh per proof, never reused | `SpendEntropy` in `core/src/prover/launch/entropy.rs` draws 512 bytes and refuses a second use of the same bytes through `entropy::entropy_was_used`, held for the life of the process |

## What is secret, and what is not

The existence of the vault and the note store is not a secret. Their contents are. A `nox1` receiving
address is public, and so is the `0x` address with everything it holds and sends. The thirteen public
words a spend carries are public too: they are what the pool decodes.

## What no amount of care here can hide

A wallet that reads the pool at all reveals that somebody used a privacy wallet. It does not reveal
who, which notes, or how much. The size of the anonymity set is a property of the pool and its
adoption, not of this app, and this page does not claim it.
