# Shield Web

The wallet as a page: the same core and the same prover as the phones, compiled to WebAssembly and
served as static files. This page says what the browser can keep of the native safety model, what it
cannot, and what the web build does instead. Where it is weaker than the apps it says so, on this page
and on the screen. Every privacy claim here is written against [02-threat-model.md](02-threat-model.md),
and a line here that contradicts it is a bug here.

## What runs where

Everything that touches a key, a note or a seed runs in the page, in the user's browser:
custody, key derivation, the note store, the scan, the proof and its verification, and signing for
the public account. The server that sends the files sends files and nothing else. It never receives
a request that carries wallet data, because there is no endpoint to receive one.

The prover runs in a Web Worker. With threads it runs on every core the browser offers, through a
rayon pool on further workers sharing one memory, which needs the page cross-origin isolated (the
headers are in [Hosting](#hosting)). Without isolation it runs on one core, slower and otherwise the
same. Either way the proof is checked before it is returned, so a page never holds bytes the
chain would refuse.

The core builds for `wasm32-unknown-unknown` with the Tor client left out on that target alone, so
a native build resolves the dependency graph it always did. In the browser build `net::tor` is a
transport that cannot be made: the type has no value, every path that would connect through it is
unreachable, and the compiler checks that. The page makes its own requests and hands the replies to
the parsers the phones use.

## Keys

Keys never leave the device. The recovery words stay the root, as in the apps, and the vault has the
same layout: a file key seals the seed, and the file key is wrapped by something the device holds.

On a phone the wrapping key lives in the Secure Enclave or StrongBox and never enters the app's
memory. A browser has no such element it will lend a page. The closest thing it offers is a WebAuthn
passkey with the PRF extension: the authenticator, which on a phone is the same secure hardware,
derives a secret from a salt the page gives it, and only after the owner is verified. The web build
derives the wrapping key from that output and wraps the file key with it, through the same
`HardwareGuard` boundary the apps implement. The wrapped key and the sealed seed are kept in IndexedDB.

What this gives up, plainly. The PRF output reaches the page's memory to be used, where a Secure
Enclave key never reaches the app's. Code running in the page while it is unlocked can read it, and
so can an extension with access to the page. A passkey synced to a cloud account is as safe as that
account. A browser without PRF support cannot wrap the key at all, and the page refuses to make a
wallet there rather than fall back to a key in storage.

Wallet data is never stored in plain text: the vault and the note store are sealed before they are
written, and the service worker never sees either.

## The network

A browser cannot run Tor, and the page says so on the screen, before the first request. Every request
the page makes goes from the user's own IP address to an RPC endpoint, which therefore learns that
address and what it asked about. The defaults are public endpoints, the same ones the native core
lists, and the user can replace each one in Settings. No request ever goes to a NØNOS server.

For IP privacy the answer is Tor Browser. Its higher security levels can turn off JavaScript or
WebAssembly, which the wallet cannot run without, so the page checks for both and says which setting
to change rather than failing silently.

The hand-off to a lander is the one place the web build cannot follow the apps. The landers are onion
services and a normal browser cannot reach an onion. The web build settles from the public account
instead, which the core already supports: the proof is sent to the pool from the user's own account,
signed in the page. What that reveals is what the apps say when a user chooses to settle it
themselves: the public account that settled this spend is linked to it in public. The amount and the
recipient of a private transfer stay hidden, since they are inside the proof. The screen says this
before the user confirms, in the same words the apps use.

## Code integrity

A web wallet is only as honest as the files the server sends on each visit. A server that is breached
or compelled can send a different page to one visitor, and that page could read everything the wallet
holds. Nothing in a browser prevents this; it can only be made detectable.

The build is reproducible: two builds of one commit on two machines give the same bytes, as the phone
libraries do. Each release publishes a manifest of every file it serves with its SHA-256, and the
hash of the manifest. `web/scripts/verify-server.mjs` fetches every file from a live origin and
compares it with a manifest built from source, so anyone can check that the site serves the real
build.

The page loads nothing from anywhere but its own origin. The Content Security Policy allows script,
style, fonts and workers from the site itself only, lets the page compile its own wasm and nothing
else, and allows network requests to any HTTPS origin, because the user chooses the endpoints. There
are no third-party scripts, no analytics and no CDN at runtime.

## Installing

The site has a web manifest and icons, so it can be added to the home screen on iPhone and Android.
A service worker caches the app shell, the HTML, scripts, styles, fonts and wasm, so the wallet opens
offline. It caches no response from an RPC and no wallet data, and a new release replaces the shell
only when every file of the new manifest has arrived.

## Warnings

Before first use, and before a wallet is made, the page shows what the apps' documentation says: the
shield runs on Sepolia only, its tokens have no value, and nothing is audited. The public account can
hold real funds on mainnet, and the page says so wherever mainnet is chosen.

## Hosting

Static files plus these headers on every response, which `web/scripts/headers.mjs` defines and the
development server sends:

| Header | Why |
|---|---|
| `Cross-Origin-Opener-Policy: same-origin` | with the next line, makes the page cross-origin isolated, the only way a browser hands it `SharedArrayBuffer` and so the threaded prover |
| `Cross-Origin-Embedder-Policy: require-corp` | as above |
| `Cross-Origin-Resource-Policy: same-origin` | no other site can embed these files |
| `Content-Security-Policy` | as described in [Code integrity](#code-integrity), the exact value in `headers.mjs` |
| `Referrer-Policy: no-referrer` | a request to an RPC does not name the page |
| `X-Content-Type-Options: nosniff` | a file is run only as the type it is served as |
| `Permissions-Policy` | passkeys and the camera, for scanning an address, and nothing else |
| `Strict-Transport-Security` | the site is reached over HTTPS only |

The wasm must be served as `application/wasm`.
