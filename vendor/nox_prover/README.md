# nox_prover

A NOX Shield spend, proved on the spender's own device. The library takes the pool's request and
the owner's seed file and returns the proof the chain verifies directly. The proof is checked
before it is returned. Nothing in it touches a file, a clock or the network, and every refusal
comes back as an error that names the problem.

One call:

```text
prove(request, seed, entropy) -> proof JSON
```

- `request` is the pool state the spend is proved against: leaves, roots, input positions,
  output values, public amount, fee, and the recipient and `fee_recipient` addresses.
- `seed` holds the owner's notes and secrets.
- `entropy` is 512 random bytes (`ENTROPY_BYTES`) from the platform's CSPRNG. It seeds the
  created notes' secrets and blindings and the proof's blinding. Never reuse it.
- The returned JSON holds the spender's new note secrets. Treat all of it as a secret.

A fee is paid to `fee_recipient`, the submitter the spender chose, and the proof binds it. A
request with a fee and no `fee_recipient`, or a `fee_recipient` beside a zero fee, is refused.

## Anonymous by default

`prove` refuses a request that breaks an anonymity default, and says which one (`src/policy.rs`,
the wallet's own anonymity rules):

- **A submitter.** A spend pays a nonzero fee to a named `fee_recipient`, so your own address never
  sends it. `"self_submit": true` opts out.
- **Standard sizes.** A public amount, and every output keyed to someone else, is
  `unit * {1, 2, 5} * 10^k`, with `unit` = 0.001 of an 18-decimal token unless the request sets
  `"unit"`. `"any_amount": true` opts out.

Each opt-out is listed in the proof JSON's `"weakened"`. Timing and fresh withdrawal addresses are
the calling wallet's job.

## The periodic cache

About a quarter of a proof on one core is spent building a tree that is identical for every spend.
`prove_keeping_cache` returns it as an 8 MB cache; `prove_with_cache` proves from it and skips the
rebuild. The cache is untrusted input:
- every chunk an opening recomputes must hash to the node stored above it;
- the proof is verified against the root the cache claims.

A wrong or tampered cache gives an error, never a proof the chain refuses. An app can build the
cache on first use or ship it.

## Platforms

| platform | interface | build |
|---|---|---|
| desktop, iOS, Android | C: `nox_prove`, `nox_free` (`src/ffi.rs`) | `cargo build --release -p nox_prover --features parallel` gives a `cdylib` and a `staticlib` |
| browser, all cores | wasm-bindgen: `initThreadPool`, `prove`, `prove_with_cache` | `python3 nox_prover/build_web.py --out <dir>` |
| browser, one core | the same, without `initThreadPool` | `python3 nox_prover/build_web.py --out <dir> --single` |
| command line | `nox_bench <request> <seed> [out]`, `NOX_CACHE=<file>` | `cargo build --release -p nox_prover --features parallel --bin nox_bench` |

### In a browser

- **Prove in a Web Worker, never on the page's main thread.** The thread pool blocks on atomics,
  which a browser forbids on the main thread, and a proof would freeze the page anyway.
- **The threaded build needs a cross-origin isolated page,** served with:

  ```text
  Cross-Origin-Opener-Policy: same-origin
  Cross-Origin-Embedder-Policy: require-corp
  ```

  Without these headers the browser gives the page no `SharedArrayBuffer`. Use `--single` for pages
  that cannot send them.

`build_web.py` writes the whole package: `nox.js`, the API a page imports; `nox-worker.js`; and
`pkg/`, the wasm. The worker, the thread pool, the randomness and the cache are handled inside:

```text
import { Prover } from "./nox.js";
const prover = await Prover.start({ cacheUrl: "./periodic.top" });
const proof = await prover.prove(request, seed);   // parsed JSON; holds new note secrets
```

A proof needs about 2.3 GB of wasm memory with the cache and 2.8 GB without it, within wasm32's
4 GB.

## What costs what

On one core, most of a proof is:
- **the query grind:** eight chained 25-bit searches, about 2^28 Keccak hashes in total, which no
  implementation removes. Split eight ways, its time varies about a third as much as one 28-bit
  search would;
- **the NTTs and the LDE.**

Both parallelize, so a device should use every core it has. The grind hashes a fixed 41-byte block
in place and allocates nothing: in a threaded wasm build, an allocation per attempt put every core
behind the allocator's one lock.
