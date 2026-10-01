# Leak ledger

Every way the wallet reveals something, with its status. An entry is eliminated, with the check that
keeps it eliminated, or bounded, with what an observer gets, or open and named as such. What is
checked and what is not is in [20-security-status.md](20-security-status.md).

A wallet claiming no leaks has not looked.

## Eliminated, with the check that holds it

| Leak | How it is eliminated | What holds it |
|---|---|---|
| a request that names a shielded address or note | the shielded balance comes from trial decryption of the whole pool history, never a query | `core/src/wallet/sync_chain.rs`, `core/src/discovery`. No call in the core asks about a note |
| where a scan starts | every scan reads the pool from its deploy block, so no request says whether the wallet is new or when it last ran | `fetch_history` in `core/src/wallet/sync_chain.rs` |
| a price feed, a token list, an icon fetch, an update check | none exists. The three coins are in the binary, and a swap quote comes from the pool reserves on chain | `scripts/check-one-destination.sh`, which refuses a URL outside `core/src/net` |
| a DNS lookup on the phone | names are resolved at the Tor exit | `core/src/net/tor/mod.rs` |
| a direct connection | every connection goes through the embedded Tor client, and there is no fallback | `core/src/net/tor`, `scripts/check-one-destination.sh` |
| the IP address of the phone, to any server | Tor | same |
| a device, install or session identifier | none is generated, stored or sent | `scripts/check-no-identifiers.sh` in CI |
| a log line or a debug print | the code of the core writes to no log and no terminal. The vendored `nonos-stark` writes ten lines of its resident memory to standard error while it builds the periodic tree, and no value of a spend | `scripts/check-no-logging.sh` in CI, and `mark` in `vendor/nonos-stark/src/air/periodic_root.rs` |
| an analytics, attribution or advertising SDK | none is linked | `scripts/dependencies.allow` in CI, and `scripts/check-package.sh` in the Android repository |
| a permission beyond what is used | three on Android, and on iOS only Face ID, which confirms the owner | `scripts/check-manifest.sh` in the Android repository, `scripts/check-privacy.sh` in the iOS repository |
| a cloud backup of the seed | the container is excluded on both platforms | the extraction rules on Android, the excluded container on iOS |
| a screenshot of a balance, on Android | `FLAG_SECURE` before the first frame | `MainActivity` in the Android repository |
| an amount in a notification | no notification is ever posted | no channel or permission is declared |
| proof randomness used twice | refused for the life of the process, by the bytes themselves | `entropy_was_used` in `core/src/entropy/used.rs` |
| a transaction signed for the wrong network | the chain id opens every batch, is checked again before signing, and is inside the signature | `core/src/evm/rpc.rs`, `send.rs`, `tx.rs`, `spec/Account.tla` |
| a signed transaction the owner did not review | the core signs only the transaction it holds under a live review id, for the account it was made for, after the platform confirms the owner | `core/src/ffi/wallet/account_send.rs`, `spec/Account.tla` |

## Bounded, with what an observer gets

| Leak | What an observer gets | The bound |
|---|---|---|
| that a privacy wallet is in use | Tor traffic from the device, its volume and its timing | unbounded in time, no content |
| a scan against a public send | a scan is many log requests, a send a few small ones | the kind of activity, not its content |
| the size of the pool | how much a full scan fetches | at least 1,186 bytes of sealed note per output |
| the number of notes held | how many outputs pass the view tag, if the timing of the scan is observable on the device | about one in 256 outputs, plus the notes held |
| the time a proof takes | a phone busy while a spend is proved | not measured on a phone to the standard in `README.md` |
| what the chain shows | nullifiers retired, commitments created, sealed notes, fee, asset, each settlement | the whole history of the pool. The anonymity set is its adoption, not a property of this app |
| the `0x` address, to the RPC servers | each read of the public account names it: balance, nonce, simulation, gas estimate | one server per read, two for a NOX send or a swap, never the IP address |
| a pending public transaction, to a private relay | sender, recipient, amount and time, before it is mined | what the chain shows once it is mined, some blocks early |
| a fee nobody else would pick | transfers linkable to each other by an unusual fee | the fee is the protocol part of the policy plus the lowest rung, the same for every wallet, with no field to type. The amount is held to standard sizes |
| the not-before time | when the proof was made, to the ten-minute grid point before it | the same for every spend proved in that slot |
| the withdrawal amount, before it settles | the fee check asks the policy about a withdrawal of that standard amount, on the scan circuits, apart from the account | one standard amount, minutes before the chain shows it, unlinked to the account |
| who lands a spend | the lander, today the only route, knows which settlements came to it, and when | anyone may land a spend, since its fee pays whoever submits it. The public Waku topic, once its specification is in, spreads that further |
| an amount split into several deposits | several standard deposits from one address, on consecutive nonces, minutes apart, which an observer can add back up | the same as one public deposit of the whole, which a standard size could not carry |
| a rewards link | a mainnet address and a testnet address tied together in the registry, by the choice of the owner | public for good. The screen names both addresses before the owner confirms |
| the store on a forensic image | how many rows the wallet holds and when it last wrote, with the contents sealed | a row count and a file time, on a device already lost |
| the vault file existing at all | that this device has a wallet | one bit, and the time the file was created |
| the network choice | whether the public account was last shown on Ethereum or Sepolia | one word, in the private container of the app |
| a copied address or hash | the next app opened can read the clipboard | 60 s, after which it is cleared. Android marks it sensitive and iOS keeps it local. A wallet nobody can copy an address out of is not a wallet, so this cost is accepted |
| a deposit and a later transfer | an observer of the chain can link the two by timing in a quiet pool | the fewer other deposits between them, the stronger the link |

## Open, and named as such

| Leak | Status |
|---|---|
| traffic shape | **half closed.** A scan runs every 300 s, give or take 60 s, while the wallet is open, so the timing of a request says the app is open and not that a person picked it up. Replies are not padded and there is no cover traffic |
| a history that lies consistently | a server that serves a pool history without a hole and reports a matching `nextLeafIndex` is believed. A second server is not asked to confirm it |
| the keyboard | a keyboard is another process and sees every character typed into an address, an amount or a recovery phrase. Correction and learning are off in every field, which keeps the text out of its dictionary but not out of the keyboard |
| an accessibility service, on Android | a service the owner granted can read the screen, and the secure flag does not stop it. The platform offers an app no way to refuse |
| a screenshot of a balance, on iOS | the platform gives an app no way to stop one. The window is covered off the foreground and while the screen is recorded |
| the memory figure, on iOS | the core cannot read a high water mark there, so the measure screen shows a footprint sampled after a proof and says so |
| the clipboard below Android 13 | the flag that hides a copied value from the system preview arrived in API 33, and the app runs from API 28. On 28 to 32 the value is still cleared after 60 s |
| the network trace | the claims about the network are claims about the code until a packet trace from a device has been taken. See [03-transport.md](03-transport.md) |

## Settling a shielded spend

The fee in a spend is a term the proof binds, and it pays whoever posts the settlement, so settling
is a market and not an identity.

| Who settles | What it costs | What it reveals |
|---|---|---|
| anyone who lands a published spend | the fee in the proof, the protocol part and one rung, set by the policy of the pool | nothing beyond what the chain shows: the payout is fixed by the proof, and the lander can steal nothing |
| the owner, from the public account, offered 30 minutes after the first publication | the gas of the settlement, 3,934,660 for the first settlement on the production pool, `0x93bd48ea…ec0d`, with the gas rung of the fee credited to that account, which `claim` collects | **the settling address is publicly tied to the spend of those nullifiers**, permanently |

The second line is the leak. The wallet offers it only once open settlement has had 30 minutes to
work, refuses it before then while a lander is on, and says what it reveals before it asks.
