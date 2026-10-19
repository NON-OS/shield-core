# Shield Web: proving in a browser, measured

Can a spend be proved in a phone's browser with the privacy model intact? This is what was
measured, how, and what it does and does not settle. Nothing here was measured on a phone; what a
phone has to show is in [On a phone](#on-a-phone).

## Setup

One machine, four cores of an Intel Xeon at 2.10 GHz, 15 GiB of memory, no swap. Chromium 141 headless,
driven by Playwright. Rust as pinned in `rust-toolchain.toml` for the native and one-thread builds,
and the nightly named in `web/toolchain` for the threaded build, which has to rebuild std with
atomics. The vector is `core/src/bench/profile/vector`, the 37-limb `transfer-eth` vector with fixed
entropy, so every run makes the same proof and a run that differs says so.

Native runs are the core's own `profile_vector` test. Browser runs are `web/bench/run.mjs`. Native peak
memory is the peak resident set of the test process. In the browser the worker reports the size of
the wasm linear memory when the proof is done, which is its peak since wasm memory never shrinks, and
the driver samples the resident set of every browser process from `/proc`. The renderer is the
process that runs the page and all its workers, and it is the one a phone would kill.

## Results

Every proof below, native and browser, came out byte for byte the pinned `proof.json`: 236,921 bytes,
Keccak-256 `14062ae3fd1a99326a6f305f784440cf17792da67fd188e025a67ab642d9a684`.

| Where | Threads | Periodic cache | Proof | Peak |
|---|---|---|---|---|
| native | 4 | held | 57.1 s | 876 MiB resident |
| native | 1 | held | 199.6 s | 814 MiB resident |
| native | 4 | built during the run | 129.4 s, the cache build included | 1,341 MiB resident |
| browser, threaded | 4 | held | 74.8 s | 935 MiB wasm, 1,079 MiB renderer |
| browser, threaded | 2 | held | 131.6 s | 931 MiB wasm, 1,076 MiB renderer |
| browser, threaded | 1 | held | 248.3 s | 929 MiB wasm, 1,073 MiB renderer |
| browser, one-thread package | 1 | held | 239.8 s | 927 MiB wasm, 1,071 MiB renderer |
| browser, threaded | 4 | none | 97.3 s | 1,314 MiB wasm, 1,442 MiB renderer |
| browser, one-thread package | 1 | none | 306.3 s | 1,307 MiB wasm, 1,432 MiB renderer |

Read across: the browser proves about 1.3 times slower than native on four threads and 1.2 times
slower on one, at about 50 MiB more wasm memory than the native process's whole resident set. The
cache, which is the same for every spend and checked on every use, saves about 380 MiB of peak and a
quarter of the time, so the web build ships it with the release and never proves without it.

The browser reported the periodic root `898b800f…2888`, the one the production verifier pins
(L1-Shield `docs/deployments.md`). One browser proof, cut to the verifier's single-call layout
(95,776 bytes) and its 13 pool words by `web/wasm/tests/verifier_args.rs`, was handed to
`verifyBatch` of the production verifier on Sepolia with `eth_call` (`web/bench/verifier-call.sh`)
through two public RPCs. Both returned true. The same call with one byte of the proof flipped reverted.

## The native build is unchanged

The core's host library built from this branch and from `main`, each the way `scripts/phone-libs.sh`
builds, are the same file, SHA-256 `74421b95…3b03`. The Tor stack is left out of the wasm build with a
target condition for this reason. A cargo feature would change the crate's build identity, and with
it the bytes of the library, even with the code the same.

## One fix the prover's repository owes

`stark_proofs/src/shield/member/tree.rs` computes `1usize << level` up to the pool depth of 32, which
overflows a 32-bit `usize`, and with this workspace's overflow checks a wasm32 proof stops there. The
wrapped value is only ever multiplied by index 0 at that level, so the result does not change, which
the byte-for-byte proofs confirm. The web build turns overflow checks off for `stark_proofs` alone
(`[profile.web]` in `Cargo.toml`) until the source takes a 64-bit or checked shift.

## On a phone

A phone browser gives a page far less memory than this machine, and none of them publishes a limit.

On iPhone, Safari kills the tab without an exception when its content process is over the limit, and
the page simply reloads. WebKit's own bug reports put what a page could reliably get well under what
a proof needs. An iPhone XS on iOS 17 reached about 1 GB of wasm memory on a first visit and 300 to
500 MB after a reload ([WebKit 269777](https://bugs.webkit.org/show_bug.cgi?id=269777)). Allocations
were refused or the tab killed at sizes that depended on reload history on iOS 16 and 17, and the
reload shrinking is believed fixed by a change that shipped in iOS 18
([WebKit 222097](https://bugs.webkit.org/show_bug.cgi?id=222097)). The open tracking bug is
[WebKit 269937](https://bugs.webkit.org/show_bug.cgi?id=269937). A proof here needs about 930 MiB of
wasm memory and a content process of about 1.07 GiB. That is above what an iOS 17 page could count on,
and whether iOS 18 or later on a given phone allows it is not known from any source; it has to be
measured.

On Android, Chrome allows a page up to 4 GiB of wasm memory on desktop
([V8](https://v8.dev/blog/4gb-wasm-memory)). Reports of much lower practical limits on phones are old
and tied to 32-bit builds of Chrome ([WebAssembly design #1397](https://github.com/WebAssembly/design/issues/1397)),
and the system's low-memory killer can end a tab under pressure. It has to be measured too.

### What the owner runs to decide

On a computer, from this checkout:

1. `web/bench/build-site.sh threads <dir> <cache>`, with the cache a first proof leaves
   (`profile_vector` writes it under the system temporary folder), and the same with `single` into a
   second folder.
2. Serve each folder over HTTPS with the headers of `web/scripts/headers.mjs`. Safari isolates a page
   only in a secure context, so a plain address on the local network is not enough.

On an iPhone with iOS 18 or later and 6 GB of memory (iPhone 15 or later), and on one with 4 GB
(iPhone 12 or 13), each freshly restarted, in Safari, and again from the home screen:

1. Open `index.html?threads=0&cache=1` on the single-thread site. Wait for the result.
2. Reload once and run it again.
3. On the threaded site open `index.html?threads=N&cache=1` with N the number of performance cores
   and then all cores.
4. Write down for each: whether the result appeared or the page reloaded, the seconds, and `wasmBytes`.
   A reload with no result is the kill.

On a mid-range Android phone with 6 to 8 GB, in Chrome, the same four steps, and `chrome://version`
to note whether Chrome is the 64-bit build.

The proof is the same on every device, so a result that appears is also checked: the page's `proof`
must hash to the Keccak above.

## Verdict

Go, with limits. On a computer, in Chromium, the browser proves the same bytes as the phones, in
75 seconds on four cores and under 1 GiB of wasm memory, and the production verifier accepts them.
The web build ships the periodic cache and proves only from it, threaded where the page is isolated.

The limit is the phone. Whether an iPhone or a mid-range Android can hold 1.07 GiB in one tab is
unmeasured, and the iPhone evidence that exists says older iOS could not. If a phone cannot, proving
does not move to a server: a proving server learns the balance and the notes, which is the leak the
whole design exists to avoid. The web build then keeps every other screen on that phone, the public
account, receiving and the balance, and says plainly that a private spend has to be proved on a
device that can: the native app on the same phone, or the web build on the user's own computer.
