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

## The network

A browser cannot run Tor, and the page says so before the first request. Each request the core
writes is sent by the browser itself, with a synchronous request from the wallet's worker, from the
user's own IP address to the endpoint the core named (`core/src/net/tor_web`). That endpoint learns
the address and what was asked. The endpoints are the core's own public defaults, and the page's
Content Security Policy allows connections to those hosts and to no other, so a changed setting or
a changed file cannot quietly send requests elsewhere. No request goes to a NØNOS server. Endpoints
the user chooses come in a later release, with a policy that lists them.

Of the nine hosts, the two thirdweb ones answer an unauthenticated request with a rate-limit notice
and no CORS header, so a browser drops their reply; natively the same notice is a reply the core
cannot read. Neither is first in any list, and the core moves to the next host when one fails, so a
read or a send goes through another endpoint.

The host of the page and Cloudflare, which serves it, see the IP address of everyone who loads the
page, and when. For IP privacy the answer is Tor Browser. Its higher security levels can turn off
JavaScript or WebAssembly, which the wallet cannot run without.

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
style, fonts and workers from the site itself, lets the page compile its own wasm and nothing else,
and allows connections to the core's endpoints only. There are no third-party scripts, no analytics
and no CDN at runtime. Text from a server or a field is always set as text, never parsed as markup.

## Installing

The site has a web manifest and icons, so it can be added to the home screen on iPhone and Android.
The service worker keeps the release's own files, so the wallet opens without a network. It caches
no reply from an RPC and none of the wallet's data, which lives sealed in IndexedDB and never passes
through it. A new release is taken only when every one of its files has arrived.

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
| `Cross-Origin-Opener-Policy: same-origin` | with the next line, makes the page cross-origin isolated, the only way a browser hands it shared memory and so the threaded prover |
| `Cross-Origin-Embedder-Policy: require-corp` | as above |
| `Cross-Origin-Resource-Policy: same-origin` | no other site can embed these files |
| `Content-Security-Policy` | as in [Code integrity](#code-integrity), with the endpoint hosts the release manifest lists |
| `Referrer-Policy: no-referrer` | a request to an endpoint does not name the page |
| `X-Content-Type-Options: nosniff` | a file runs only as the type it is served as |
| `Permissions-Policy` | passkeys and writing to the clipboard, and every other feature off |
| `Strict-Transport-Security: max-age=63072000` | this host over HTTPS only, without binding the rest of its zone |

Files under the release directory, whose path changes with their content, are cached as immutable.
`index.html`, the service worker, the web manifest and the two release files are never cached
without asking again. The wasm is served as `application/wasm`. No file is over 25 MiB.
