# Legal

Draft. This text is to be reviewed by a lawyer before any public release, and it does not take
effect as written until then.

## Licence and warranty

The software in this repository is licensed under the GNU Affero General Public License, version
3 or any later version. It is provided as is, without warranty of any kind, express or implied,
including the warranties of merchantability and fitness for a particular purpose. The full terms
are those of the licence.

## Test network

The NOX Shield pool this software uses runs on Sepolia, an Ethereum test network. Tokens on it
have no value. Beta mode on the pool is ended, in transaction
`0xcbd9542ec16f00ce7b1e3777066e7f62716ab77d2299619a240b553deb29c9d5` at block 11,775,568, so no
refund or wind-down can happen.

## No advice and no offer

Nothing in this software, this repository or its documents is financial, investment, tax or
legal advice, or an offer or solicitation to buy or sell any token. Nothing here makes any
statement about the price or the future value of any token.

## Responsibility of the user

Users are responsible for complying with the laws that apply where they live and act, including
sanctions and export controls. Privacy software has been the subject of sanctions in some
jurisdictions. A user who is unsure whether they may use this software should take legal advice
first.

## Privacy policy

The app collects no analytics, no crash reports and no personal data, and it has no account with
the developers. Its keys, recovery words and notes stay on the device.

All of its network traffic travels over the Tor network, from a Tor client built into the app.
The third parties it contacts are:

- the Tor network, whose relays carry the traffic
- public Ethereum RPC providers, which answer reads of public chain state: `publicnode.com`,
  `thirdweb.com`, `blxrbdn.com` (bloXroute), `blastapi.io` (Bware Labs) and `ethpandaops.io`
- on Ethereum mainnet, the private transaction relays `rpc.flashbots.net` (Flashbots) and
  `rpc.mevblocker.io` (MEV Blocker), which receive signed transactions before they are mined
- on Sepolia, the relayer a user hands a private transfer to, which receives the proof and the
  sealed notes

Over Tor, none of these learn the IP address of the user. An RPC provider learns which public
chain state was read and when. A relay learns a signed transaction, which becomes public when it
is mined. A block explorer page is opened only when a user chooses to open it, in their own
browser, and is then governed by the terms of that site.

## Third-party software

The app ships open-source code under its own licences, among them the Rust crates listed in
`scripts/dependencies.allow`, the prover sources in `vendor/`, and the libraries of each app. Each
app shows the licence of every component it contains, generated at build time, under Settings,
Licences.

## Encryption and export

The app contains encryption: ChaCha20-Poly1305, X25519, ML-KEM-768, BLAKE3, Keccak, secp256k1
signatures, TLS and a STARK prover. Its iOS build declares `ITSAppUsesNonExemptEncryption` as
true and relies on the exemption for publicly available source code, since all of its source is
published under the AGPL. The export classification is to be confirmed by counsel before
submission to any app store.
