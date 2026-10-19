# Shield Web

The wallet as a page, at https://shield.nonos.app. It runs the same core and the same prover as
the phones, compiled to WebAssembly and served as static files. This page says what a browser keeps
of the native safety model, what it cannot keep, and what the web build does instead. Where it is
weaker than the apps it says so here and on the screen. Every privacy claim is written against
[02-threat-model.md](02-threat-model.md), and a line here that contradicts it is a bug here.

## What runs where

Everything that touches a key, a note or a seed runs in the user's browser: custody, key
derivation, the note store, the scan of the pool, the proof and its check, and signing for the public
account. It is the native `Wallet` of `core/src/ffi`, unchanged, held by a module worker
(`web/app/js/wallet/worker.js`) and called by name through `web/wasm`. The server that sends the
files sends files and nothing else, and has no endpoint that could receive wallet data.

Three things a phone has and a page does not are supplied for the wasm32 target only, so a native
build compiles exactly what it did before; the host library from this branch and from `main` is the
same file, byte for byte.

- Files. `crate::fs` is std's file system natively and an in-memory one in the browser. The worker
  loads the stored files before the first call and, after each call, writes every changed file to
  IndexedDB in one transaction, so storage never holds half of a call.
- The clock, through `crate::time`, which is the page's clock in the browser.
- Threads for the account search, through `crate::threads`, which runs that work in turn in the
  browser. The prover's own threads are a rayon pool on Web Workers sharing one memory.

## Keys

Keys never leave the device. The recovery words stay the root, as in the apps, and the vault has
the same layout: a file key seals the seed, and the file key is wrapped by something the device
holds.

On a phone the wrapping key lives in the Secure Enclave or StrongBox and never enters the app's
memory. A browser has nothing of the kind it will lend a page. The closest it offers is a passkey
with the WebAuthn PRF extension: the authenticator derives a 32-byte secret from a salt the page
fixes, and only after the user is verified. The web build wraps the file key under that secret
with ChaCha20-Poly1305 (`web/wasm/src/guard`), through the same `HardwareGuard` boundary the apps
implement. The secret is used for one wrap or unwrap and wiped.

What this gives up, plainly. The PRF output passes through the page's memory, where a Secure
Enclave key never reaches the app's. Code running in the page while it is unlocked can read it, and
so can a browser extension allowed into the page. A passkey synced to a cloud account is as safe as
that account. A browser without PRF cannot wrap the key at all, and the page then makes and opens no
wallet rather than fall back to a key in storage. Sends, deposits and showing the recovery words ask
the passkey to verify the user first, where the apps ask for Face ID or the screen lock.

## What storage holds

The browser's storage holds what a phone keeps on disk: the sealed vault, the note logs and the
account book, written by the core. One thing in it exists nowhere else. A deposit's note is kept only
where the deposit was made, until it is spent, and the recovery words do not bring an unspent
deposit back; that is the core's design today, the same in the apps. A browser can clear a site's
storage on its own, and Safari does after seven days without a visit unless the page has been added
to the home screen. So the welcome screen recommends adding the page to the home screen before a
wallet is made, the page asks the browser to keep its storage when a wallet is made or restored, and
Settings says whether the browser agreed.

While the active account holds a deposit's note, Home and the shield say how much the words cannot
bring back, with "Make it recoverable": a private send of a standard amount to the wallet's own
address. Both notes that send makes, the payment and the change, are sealed to the wallet's key, so
a restore finds them. The web build reads which notes came from deposits from the store's own
deposit rows (`core/src/store/deposited.rs`, compiled for wasm32 only). A send uses the smallest
note that covers it, so with other notes held it may leave the deposit's note in place, and the line
stays until that note is spent.

## The network

A browser cannot run Tor. The web build sends the core's requests through the Nym mixnet instead,
by default, every time the page opens. Every chain read and every send the core makes goes this
way. There is no relayer to reach on the web: a spend is settled from the user's own account, so
its settlement is one more send. No request goes to a NØNOS server.

The core lists seven hosts: three for mainnet reads, two private relays for mainnet sends, and
two Sepolia servers that take both reads and sends. Each answers a browser's request with a CORS
header. A NOX send on Sepolia reads the token from both Sepolia servers and needs them to agree, so
while either is down it is refused and nothing is sent.

### What Nym hides and what it does not

The RPC providers and the private transaction relays see a Nym exit node's address, not the
user's. TLS runs from the page to the endpoint inside the mixnet, so the exit sees ciphertext and
the endpoint's address. The entry gateway sees the user's IP address and that it uses Nym, but not
what is asked or of whom. Between the gateway and the exit, the mixnet's nodes reorder and delay
packets, and the client sends cover traffic while the tunnel is up.

What it does not hide: Cloudflare and the host of the page see the IP address of everyone who loads
the page, and when, since the page itself comes over the plain web. What happens on chain is public,
as always. An endpoint still learns the `0x` address a read names and the time of the request, as in
[02-threat-model.md](02-threat-model.md) section 3, without the IP address. The exit and the
endpoint can see that requests come from Nym, and an endpoint may refuse or limit them.

One tunnel carries every request of a session, through one exit. The apps keep a circuit per
account and per network, so no exit or endpoint sees two accounts' reads come the same way. On the
web, an endpoint that sees two addresses read from the same exit in one session can guess they
belong together. A new tunnel, and so a new exit, comes with each new page and after each failure.

Each request takes a few seconds longer: the mixnet delays every packet on purpose, and one request
over it is several round trips, for TCP, TLS and HTTP. The first waits for the tunnel to start. How
much longer is not measured yet; [web-measurements.md](web-measurements.md) says why and how.

### How a request travels

The core is unchanged (`core/src/net/tor_web`). It writes an HTTP/1.1 request and sends it with
the browser's synchronous `XMLHttpRequest` from the wallet's worker. In that worker the name is a
stand-in (`web/app/js/wallet/sync-request.js`): it posts the request to the page on a port of its
own and blocks on `Atomics.wait` over a `SharedArrayBuffer`, which the page can hand over because it
is cross-origin isolated. The page (`web/app/js/route/bridge.js`) sends it through mix-fetch in a
worker of its own (`web/app/js/route/worker.js`), writes the status and body into the shared buffer
and wakes the wallet's worker, whose core reads the reply as it would any other. The core's own
limits apply: a reply above 16 MiB is refused.

The tunnel starts with the first request. Each tunnel is a fresh Nym client under a random name,
registered with one gateway from a pinned set of eight, starting at a random one, and it picks an
exit from Nym's directory. Its keys live in IndexedDB as `wasm-client-storage-shield-…` and are
deleted when the tunnel ends, so two sessions share no Nym identity.

### Never direct without asking

When a request fails through Nym, the page ends the tunnel and tries again through a new one and
the next gateway, three times within 150 seconds. Then it stops and asks: "Nym isn't reachable.
Connect directly? Your IP address becomes visible to the network provider." "Stay on Nym" is the
first answer and the one in focus; it fails that request and the rest of that wallet call.
"Connect directly" sends that one request from the browser. "Directly until I close the page" turns
Nym off for the rest of the session. No answer is stored, and nothing goes direct without one.

Settings shows the route, the gateway in use and whether the tunnel is up, with a switch that turns
Nym off. The switch holds until the page is closed, like the prompt's answer, so the next visit is
on Nym again. The status line at the foot of every screen says "nym mixnet" or "browser, direct".

### The Content Security Policy

The policy names every host the page may connect to: its own origin, Nym's directory
(`validator.nymtech.net`, and Nym's two fallbacks `nym-frontdoor.global.ssl.fastly.net` and
`cdn1.media-platform.net`), the pinned gateways as `wss://<host>:9001`, and the core's RPC
endpoints. The gateways come from `web/app/js/route/hosts.js`; each is a different operator in a
different country, and `web/scripts/check-gateways.mjs` says which are still listed as usable.

A pinned set is tighter than `wss:` or `wss://*:9001` for any gateway, which a changed file could
use to send data anywhere. What it costs: the operators of eight gateways see the IP addresses of
every Shield Web user who reaches them, where an unpinned client would spread over about 550. Each
gateway sees only its own share, and never the requests. A pinned gateway that leaves the network
costs a retry, and a release with fewer than half its gateways usable should pin again.

The RPC hosts stay in the policy, because the direct fallback is the browser's own request and the
policy cannot tell a request the user allowed from one they did not. What keeps a request off them
while Nym is on is the code above. `web/tests/route.mjs` checks it in Chromium's net log: with Nym
blocked, no RPC host is named before the user answers "Connect directly".

The core's two thirdweb hosts answer an unauthenticated request with a rate-limit notice. Through
Nym that is a reply the core cannot read, as it is natively, and directly the browser drops it for
want of a CORS header. Neither is first in any list, and the core moves to the next host.

For IP privacy from Cloudflare too, the answer is Tor Browser. Its higher security levels can turn
off JavaScript or WebAssembly, which the wallet cannot run without.

### The mixnet client

`@nymproject/mix-fetch` 3.0.0, the newest release (published 8 October 2026), and the
`@nymproject/mix-tunnel` 0.3.0 it pins, both Apache-2.0, pinned in `web/package.json` and its lock
file. mix-fetch is a 2 KB wrapper. mix-tunnel ships the Nym client's worker as base64 inside one
18 MB module, with smolmix-wasm, Nym's Rust client, as base64 inside the worker. The wasm says it
was built from `nymtech/nym` at `564b2ede` on 7 October 2026.

The browser would start that worker from a `blob:` URL, which `worker-src 'self'` refuses. So
`web/scripts/nym.mjs` writes the worker out as `nym/tunnel.js` (13.6 MB, 4.1 MB gzipped, of which
10.1 MB is wasm), replaces the one line that made the blob with one that starts that file, points
mix-fetch's import at the file beside it, and checks all three against pinned SHA-256s. The files
are served from the page's own origin, listed in the release manifest and checked by the service
worker like every other file. The wasm compiles under `'wasm-unsafe-eval'`, which the page already
allows for its own.

What the client does, from its source at that commit (`wasm/smolmix`, `common/network-defaults`)
and from Chromium's net log:

- TLS ends inside the client's wasm: rustls with the RustCrypto provider and the `webpki-roots`
  store, AEAD suites with forward secrecy only (`wasm/smolmix/src/tls.rs`). The exit forwards IP
  packets and sees ciphertext, the destination's address and port, and the name in the TLS
  handshake.
- Host names are resolved through the tunnel by DNS over HTTPS to Quad9, Cloudflare or Google, so
  the resolver learns the name from an exit's address.
- It reaches Nym's directory over HTTPS for the gateways, the exits and their versions, and holds
  one WebSocket to its entry gateway. Nothing else leaves the browser.
- Its exits, IP packet routers, enforce Nym's exit policy
  (`https://nymtech.net/.wellknown/network-requester/exit-policy.txt`, v1.12.0 of 5 August 2026):
  port 443 is open to any address but about 430 ranges listed by Spamhaus.
- It speaks HTTP/1.1 only, with browser-shaped default headers, and has WebSockets too, which the
  wallet does not use.
- It starts in a worker under COOP, COEP `require-corp` and this CSP, compiles its wasm, reads the
  directory and opens its gateway's WebSocket, as `web/tests/nym.mjs` shows. A whole request
  through it has not been made yet; [web-measurements.md](web-measurements.md) says why.

Left to choose a gateway at random, 3.0.0 picked one without a host name for wss and failed
("does not support the wss protocol"). The pinned set avoids that.

The licences screen lists the two packages, the JavaScript mix-tunnel bundles (Comlink and two
Rollup helpers) and the 533 crates smolmix-wasm links, made by `web/scripts/nym-licences.mjs` from a
Nym checkout at that commit and kept in `web/nym`. They are MIT, Apache-2.0, BSD, ISC, Zlib,
Unicode, CC0 and CDLA-Permissive-2.0, with two MPL-2.0 crates, `colored` and `option-ext`. None is
GPL.

The hand-off to a lander is the one step the web build cannot take as the apps do. The landers are
onion services, and a normal browser cannot reach an onion; the transport refuses one rather than
try. The web build settles each spend from the user's public account instead, which the core
already supports as "settle it yourself". The settlement names that account in public and links it
to the spend. The amount and the recipient of a private transfer stay inside the proof, and the
lander's part of the fee comes back to the account that settles. The screen says this before the
user confirms.

## Proving on a phone

A proof needs about 1 GiB of memory in the page ([web-measurements.md](web-measurements.md)). A
computer's browser gives that. A phone's may end the page without warning long before. So on a
phone or tablet a private send waits until one proof of the pinned test vector has finished in that
browser. The test proof spends nothing, since its notes exist in no pool. If the page reloads
instead, a mark set before the proof is still there on the next visit, and private sends stay
refused on that device with a pointer to the NØNOS app or a computer. Deposits, receiving and the
public account still work there. Nothing is ever proved on a server: a proving server learns the
balance and the notes, which is the leak the design exists to avoid.

The prover starts from a periodic cache that the release ships in chunks. Each chunk's SHA-256 is
checked against the release manifest before use, and the prover checks the whole cache against the
root it was built for. Without a cache that checks out, the page refuses private sends rather than
build one, which would take another 380 MiB.

## Code integrity

A web wallet is only as honest as the files the server sends on each visit. A server that is
breached or compelled can send one visitor a different page, and that page could read everything
the wallet holds. Nothing in a browser prevents this; it can only be made detectable.

The build is reproducible: `web/scripts/release.mjs` builds the site from a clean checkout, and two
builds of one commit give the same files and so the same manifest hash. The release manifest lists
every file the site serves with its size and SHA-256, and `release.json` gives the manifest's hash.
`web/scripts/check-live.mjs` fetches every file from the live site, compares each one with the
manifest, and checks the headers the page depends on. Settings in the page shows the release and its
manifest hash.

The page loads nothing from anywhere but its own origin. The Content Security Policy allows script,
style, fonts and workers from the site itself, lets the page compile its own wasm and the Nym
client's and nothing else, and allows connections to Nym's directory, the pinned gateways and the
core's endpoints only, as in [The network](#the-network). The one third-party code the page runs,
the Nym client, is served from the site, listed in the manifest and checked like every other file.
There are no analytics and no CDN at runtime. Text from a server or a field is always set as text,
never parsed as markup.

## Installing and updating

The site is an installable web app: a manifest with the apps' name and icon, the dark colours, iOS
launch images for current iPhones and iPads, and layout inside the safe areas. On iOS it is added
from Safari's Share sheet; Chrome and Edge offer Install, which Settings also shows.

The service worker keeps one release's files, so the wallet opens without a network, and says on
screen that it is offline; anything that reads the chain says it needs one. Each file is checked
against the release manifest's SHA-256 before it is kept, and kept with the headers it was served
with, so the page stays cross-origin isolated, and the threaded prover keeps working, when it opens
from the cache. The worker caches no reply from an RPC and none of the wallet's data. Each release is
a new worker that installs beside the old one and waits: the page shows "Update ready", and only when
the user takes it does the new release open, with one reload, so two releases never serve one page.

## Locking and reading the pool

As in the apps, the wallet locks after the idle time chosen in Settings, five minutes unless changed,
and when the page is hidden, unless a proof is running. It reads the pool every five minutes or so
while the page is open and nothing else runs. A closed page reads nothing; the next open reads the
pool when the shield is shown.

## The look

The screens are the apps' screens, with their copy, their order and their states, drawn with their
own tokens: the ink ground, the cyan, Geist and JetBrains Mono, the numbered bar, the recoloured Etna
photographs, and the round actions with the Android app's glyphs. The photographs are by gnuckx,
under CC BY 2.0, recoloured by NØNOS, and credited in About as in the apps. Where a browser forces a
difference, the screen says so: a passkey instead of the Secure Enclave or the Keystore, settling
from the public account instead of a lander, and the phone proof check.

## Warnings

Before a wallet is made or opened, the page shows what this release is: the shield runs on Sepolia
only and its tokens have no value, nothing is audited, and what a web wallet trusts that the apps do
not, including the host and Cloudflare seeing every visitor's IP address. The public account can
hold real funds on mainnet, and every screen that acts on mainnet says so.

## Hosting

Static files and the headers in `web/scripts/headers.mjs`, which the release writes into
Cloudflare Pages' `_headers` and the development server applies the same way.

| Header | Why |
|---|---|
| `Cross-Origin-Opener-Policy: same-origin` | with the next line, makes the page cross-origin isolated, the only way a browser hands it shared memory, for the threaded prover and for the wallet's worker to wait on its requests |
| `Cross-Origin-Embedder-Policy: require-corp` | as above |
| `Cross-Origin-Resource-Policy: same-origin` | no other site can embed these files |
| `Content-Security-Policy` | as in [Code integrity](#code-integrity), with the endpoint hosts and the Nym hosts the release manifest lists |
| `Referrer-Policy: no-referrer` | a request to an endpoint does not name the page |
| `X-Content-Type-Options: nosniff` | a file runs only as the type it is served as |
| `Permissions-Policy` | passkeys and writing to the clipboard, and every other feature off |
| `Strict-Transport-Security: max-age=63072000` | this host over HTTPS only, without binding the rest of its zone |

Files under the release directory, whose path changes with their content, are cached as immutable.
`index.html`, the service worker, the web manifest and the two release files are never cached
without asking again. The wasm is served as `application/wasm`. No file is over 25 MiB.
