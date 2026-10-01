# Threat model

What each observer learns, from the operating system of the phone to anybody reading the chain.
Every other privacy claim in this repository is written against this page, and a line elsewhere
that contradicts it is a bug there. What is checked and what is not is in
[20-security-status.md](20-security-status.md).

The seven positions are the operating system of the phone, the network path, the RPC servers, the
private transaction relays, whoever lands a spend, the chain, and a person holding an unlocked phone.

## 1. The operating system of the phone

An attacker here has code running on the device outside the sandbox of the app, or has the
cooperation of the platform.

They learn everything. While the wallet is unlocked the derived keys are in the memory of the app.
During a scan the note plaintexts are too, and during a proof the prover holds the whole witness.
The witness text and the proof randomness are zeroed on drop, which narrows the window and does not
close it. A proof holds its trace for as long as it runs.

One thing stays out of reach even here. The vault at rest is sealed under a file key the secure
element wraps, so an attacker who can read the file system and not the running process gets a
ciphertext. The keystore key requires the owner.

This position is not defended against and cannot be. A rooted or jailbroken device, or a platform
that serves a targeted build, ends the analysis. The app keeps the window short: no key cached
across a lock, no derived key written to storage, no cloud backup.

## 2. The network path

An attacker who watches the traffic of the device, or who runs the guard relay the Tor client
chose.

They learn that the device runs Tor, and when, and how much. They see the volume and the timing of
the guard connection. That is enough to say a privacy tool is in use and roughly when, and enough to
tell a full pool scan, a long series of fixed-shape log requests, from a public send, a few small
requests.

They do not learn which server is asked, since it is inside the circuit. They do not learn an
address, an amount, a note or a key. There is no DNS lookup on the phone to correlate. Names are
resolved at the exit.

The weakness is traffic volume over time, which is a fingerprint. Scans run every 300 s, give or
take 60 s, while the wallet is open, so the timing says the app is open and not that a person picked
it up. The app does not pad replies and sends no cover traffic, so the shape of activity stays
visible while its content does not.

## 3. The RPC servers

The servers listed in [03-transport.md](03-transport.md). They answer over TLS inside Tor, so they
never learn the IP address of the phone.

For the shielded pool they learn a scan and nothing else. Every wallet sends the same requests: the
head block, `nextLeafIndex`, and the four event histories of the pool from its deploy block to the
head. The server learns that some client scanned, not what it found.

For the public account they learn the `0x` address. A balance, a nonce, a simulation as the sender
and a gas estimate all name it, and each read reaches the server with the time of the request. A NOX
send and every swap read the token and pool state from two servers, so two providers see that read.
Circuits are isolated per network, so a read on Sepolia and a read on Ethereum do not share an exit.

A server can also act: withhold, lie or refuse. A pool history with a hole, or with fewer leaves than
`nextLeafIndex` says, is refused and the next server is tried. A server that lies consistently about
both, from the same answer, passes that check. No second server is asked to confirm the history, and
that stays open. A server that answers for another chain is refused outright. For a NOX send, two
servers must agree on the token state, and for a swap also on the pool reserves, within 1%. A server
that lies about a balance or a reserve can make a review refuse or quote badly. It cannot move money,
because the amount and the recipient come from the owner, and a swap carries a minimum the chain
enforces.

## 4. The private transaction relays

On Ethereum mainnet, Flashbots Protect and then MEV Blocker. They receive a signed transaction
before it is mined and learn the sender, the recipient, the amount and the time, all of which become
public once it is mined. They keep the transaction out of the public mempool, where a pending sale
of NOX could be sandwiched. The wallet later asks them, by hash, whether a recent send is still held,
to choose the next nonce.

## 5. Whoever lands a spend

A spend is published for anyone to land, since its fee pays whoever submits the settlement
(`address(1)` in the proof). Today it goes to the lander onion service, and the public Waku topic
comes first once its publish specification is in this repository. Whoever holds the publication
gets the proof, its 37 public limbs and the two sealed notes, and the time they arrived. That is
what the chain shows once the spend settles, a little earlier. It does not learn the sender, the
receiver or the amount, and it cannot change the amount, the receiver or the fee, which the proof
binds. Over Tor it does not learn the IP address of the phone.

A lander can refuse or delay. The wallet publishes the spend again after 15 minutes, and after 30
offers the owner to settle it from the public account. That last step is weaker for privacy: the
settling address is tied to the spend in public, for good, and the screen says so before it asks.
If nothing lands, take back returns the notes.

## 6. The chain

Anybody reading the pool, forever.

They learn the nullifiers retired, the commitments created, the sealed notes, the fee, the asset,
the not-before time, and each settlement. The fee is the protocol part plus the lowest rung of the
gas ladder, the same for every wallet, so it says nothing about the wallet. The not-before time is the ten-minute grid point
before the proof, the same for every spend proved in that slot. They learn the size of the anonymity set, because it is the whole history of
the pool.

They do not learn who sent what to whom, or how much, unless the pool is small enough that the set
of possibilities is small. That privacy property is outside the control of the app. A transfer in a
pool with four users is not private, whatever the proof says.

A withdrawal puts an amount and an EVM address on the chain, and is as private as any public
transaction, which is not private at all. A deposit does the same on the way in. An amount split
into several standard deposits shows several deposits from one address, minutes apart, which an
observer can add back up.

A rewards link puts a mainnet address and a testnet address side by side in the registry, by the
choice of the owner, with a signature from each side. Whatever either address does is then tied to
the other. In a quiet pool, a
deposit followed soon by a transfer can be linked by timing alone.

The public account is an ordinary Ethereum account. Everything it holds and sends is public, on both
networks.

## 7. A person holding the unlocked phone

They see the balances and the addresses, and they can prove a shielded spend, because the wallet is
open. A public send or swap asks the platform for the owner again before it is signed, so a phone
handed over unlocked cannot send public funds without the face, the finger or the passcode of the
owner. They can read the recovery words only if the screen that showed them once is still up, and it
is not after it is dismissed.

They can copy the vault and the note store off the device, and both are useless elsewhere. The key
of the vault is in the secure element, and the key of the store is derived from the seed.

They cannot take a screenshot of a balance on Android. On iOS they can, because the platform gives
an app no way to block one.

The answer to this position is the lock and the keystore. Locking drops the session and every
derived key, and unlocking asks the keystore again.

## What is not modelled

Timing across positions. An observer who is both the network path and a server can correlate a
request with a burst from a particular guard connection. Nothing in the app prevents that. Cover
traffic would.

Side channels on the device. A proof is minutes of heavy arithmetic with a distinctive power and
thermal signature, which already says a proof is being made.

Compromise of the primitives. X25519, ML-KEM-768, ChaCha20-Poly1305, BLAKE3, SHA3, Keccak,
secp256k1, Poseidon and the STARK are assumed sound. Notes are sealed with X-Wing, so a note stays
sealed while either X25519 or ML-KEM-768 holds. The Merkle digests of the production pool are 32
bytes.
