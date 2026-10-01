# Transport

How a request leaves the phone: the embedded Tor client, the servers it asks, the checks on every
reply, and open settlement through the lander onion service. Network metadata is the leak a proof
cannot cover, so every request the wallet makes goes through Tor. What is checked and what is not
is in [20-security-status.md](20-security-status.md).

## The Tor client

The core embeds Arti, the Rust implementation of Tor (`arti-client` 0.46.0), in `core/src/net/tor`.
It bootstraps from the live consensus, checks the signatures of the directory authorities itself,
and chooses its own guard, middle and exit relays. Guard state and the directory cache live in the
private directory of the app, so the guard persists between launches, which resists an attacker
rotating a wallet onto a guard it controls. No proxy app sits between the wallet and the network.

Each purpose has its own isolated circuits, so the exit that carries one kind of request never
carries another:

| Purpose | What travels on it | Where it is used |
|---|---|---|
| `Scan` | the event history of the shielded pool, and the fee schedule, the percentages and the fee check of its policy | `core/src/wallet/sync_chain.rs`, `core/src/net/fee_quote.rs` |
| `Deposit` | reads of pool state before a deposit, and of what an address could recover | `core/src/wallet/deposit_read.rs`, `recover.rs` |
| `Mainnet` | every read and send of the public account on Ethereum, and the ERC-1271 check of a contract wallet that signs a rewards link | `core/src/evm/network.rs`, `core/src/wallet/rewards/contract.rs` |
| `Sepolia` | every read and send of the public account on Sepolia, the reads of the rewards registry, and a link or a split deposit | `core/src/evm/network.rs`, `core/src/wallet/rewards/read.rs`, `core/src/evm/shield_batch.rs` |
| `Relay` | the publication of a proof to the lander onion service, and its status | `core/src/net/relay`, `core/src/ffi/wallet/publish.rs` |

Every connection is TLS end to end inside the circuit, through rustls with the Mozilla root store
from `webpki-roots`, so the exit relay sees ciphertext. Host names are resolved at the exit, never on
the phone. A connection, a read or a write that makes no progress for 30 s is abandoned and the next
server is tried.

No wallet flow makes a direct connection. When Tor cannot reach any server, the call fails and the
screen says the network could not be reached over Tor. `scripts/check-one-destination.sh` fails CI
when code outside `core/src/net` names a socket API or a URL.

## Who is asked

The RPC servers are listed in the code and nowhere else. The test
`every_listed_rpc_answers_over_tor_for_its_own_chain` in `core/src/evm/rpc.rs` checks that each one
answers over Tor for its own chain.

| Use | Servers, tried in this order | Source |
|---|---|---|
| Shielded pool history, Sepolia | `ethereum-sepolia-rpc.publicnode.com`, `rpc.sepolia.ethpandaops.io` | `core/src/net/pool.rs` |
| Public account reads, Ethereum | `ethereum-rpc.publicnode.com`, `1.rpc.thirdweb.com`, `eth.rpc.blxrbdn.com`, `eth-mainnet.public.blastapi.io` | `core/src/evm/network.rs` |
| Public account sends, Ethereum | `rpc.flashbots.net`, then `rpc.mevblocker.io` | same |
| Public account reads, Sepolia | `ethereum-sepolia-rpc.publicnode.com`, `rpc.sepolia.ethpandaops.io`, `sepolia.rpc.thirdweb.com` | same |
| Public account sends, Sepolia | `ethereum-sepolia-rpc.publicnode.com`, `sepolia.rpc.thirdweb.com` | same |

On mainnet a signed transaction goes to a private relay, which keeps it out of the public mempool
until it is mined, so a NOX sale cannot be sandwiched on its way in. Flashbots accepts at most 8
calls in a batch, so the lookups of held sends go 4 at a time (`core/src/evm/held.rs`).

## What every batch checks

Every batch to a public account server opens with `eth_chainId`. A server that answers for another
chain is refused for the whole batch, and the batch is not retried elsewhere, because a server that
lies about its chain is a reason to stop. The chain id is asked again of the send relay just before
signing, and the transaction is signed with the chain id of the selected network, so a transaction
signed for one network is invalid on the other.

The pool history is accepted only whole. Its leaves must be `0` to `nextLeafIndex - 1`, read at the
same block, or the server is refused and the next one is tried. A reply above 16 MiB is refused
before it is held (`core/src/net/rpc/http.rs`).

## Open settlement

Every proof pays its fee to `address(1)`, whoever submits its settlement, so the wallet holds no
lander address and anyone may land a spend. `publish_spend` hands the spend over through Tor and
never direct, and records when (`core/src/ffi/wallet/publish.rs`). The route today is the five landers
of the production pool, each a Tor onion service reached on port 80 on the relay circuits, tried in
this order and given 20 seconds each, a connection tried again within that time while the route to
the service is built (`core/src/net/relay/landers.rs`):

1. `mforujillfk4w5h2zqgxdzendn3qb2zes4r2h57ownojshhmtcdzgdyd.onion`
2. `lfpw5uoslfiqmwsc7o2d2qts3grmfnixrhae3hkgkv6x4dlxpvafp4yd.onion`
3. `7ywwruseitmycfjwh2upbecetm6edej7pkxpp4xtzmtioes4ubs63kad.onion`
4. `g7uyxmffgim7sneprrkdp4ecshupvd3kuaadho6f7e2gcd3gazimriyd.onion`
5. `ewjq3ue43pclh6qyx3triup7org64nykbjgy7tmderlzzx27kstfdiqd.onion`

A spend may reach more than one lander, and the pool lands it once.
The public Waku topic goes first once its publish specification is in this repository, with the
onion as its fallback.

The onion address authenticates the service end to end, so the requests are plain HTTP inside Tor.
Before a proof is handed over, `GET /v1/info` must name the production pool and report
`fee_to_submitter_accepted: true`. A lander that does not, or cannot be reached, is passed over for
the next, and nothing is posted to it. `POST /v1/handoff` carries the proof, its
37 public limbs and the two sealed notes, built from the files of the spend and checked for size
first (`core/src/wallet/relay_body.rs`). The lander answers 202 with an id, or 400 with a reason,
which a screen shows as printable text of at most 200 characters. `GET /v1/handoff/<id>` reports
queued, scheduled, settling, settled or refused, and the settlement hash once there is one.

`follow_spend` then reads the whole history of the pool on the scan circuits, the same requests
every wallet makes, and looks for both nullifiers of the spend. It never asks a server about a
nullifier. A spend that has not landed 15 minutes after its latest publication is published
again, and 30 minutes after its first publication the owner is offered to settle it from the
public account (`core/src/ffi/wallet/settle_self.rs`), which links that account to the spend in
public. The timers are in `core/src/wallet/publish/next.rs`.

An onion connection may take up to 120 s to open, since it fetches the descriptor and builds two
circuits to a rendezvous. A stalled read or write still gives up after 30 s. The request is flushed
after it is written, because a Tor stream holds written bytes until it is flushed and an onion
service has no TLS layer to do it. The test `the_lander_answers_over_tor_and_takes_the_submitter_fee`
checks the launch lander live.

## The rewards registry and the fee policy

The registry and the policy are contracts, read with `eth_call` like any other. The registry reads
name the active account and the mainnet address it would link, so they travel on the circuits of
the Sepolia account. A contract wallet that signs a link is asked on mainnet, on the circuits of the
mainnet account. The fee policy is read on the scan circuits: the schedule, the percentages, and
`settlementFee` for the fee about to be proved, which for a withdrawal names its standard amount.

## What is never a network call

A block explorer page. The core returns a link, and a person opens it in their own browser if they
choose to.

## The proxy client

`core/src/net/socks5`, `endpoint.rs`, `policy.rs` and `onion.rs` are a SOCKS5 client and an endpoint
policy for a platform that provides its own proxy. A proxy must be on loopback, a Tor route must name
an onion service, and there is no direct mode. They are reachable only through `proxy_answers` in
`core/src/ffi/proxy.rs`, which probes a proxy port on loopback. No wallet flow calls them.

## What has to be shown

A packet trace from a device while the app creates a wallet, scans, reviews a public send and sends
it, in which a passive observer sees Tor connections and nothing that identifies an account. That
trace is not taken, and until it is, the network claims on this page are claims about the code.
