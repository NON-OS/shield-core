// NONOS Operating System (AGPL-3.0-or-later)
//
// The prover's worker: loads the wasm, starts the thread pool, and proves.
// Spoken to only by nox.js. Proving happens here and not on the page because
// the thread pool waits on atomics, which a browser forbids on the main
// thread, and a proof would freeze the page for its whole length anyway.

import init, * as nox from "./pkg/nox_prover.js";

let cache = null;

async function handle(msg) {
  switch (msg.op) {
    case "init": {
      await init();
      if (msg.threads > 0) {
        if (typeof nox.initThreadPool !== "function") {
          throw new Error("this package is the single-thread build; start with { singleThread: true }");
        }
        await nox.initThreadPool(msg.threads);
      }
      cache = msg.cache;
      return true;
    }
    case "prove":
      return cache
        ? nox.prove_with_cache(msg.request, msg.seed, msg.entropy, cache)
        : nox.prove(msg.request, msg.seed, msg.entropy);
    default:
      throw new Error(`unknown operation ${msg.op}`);
  }
}

onmessage = async ({ data }) => {
  try {
    postMessage({ id: data.id, ok: true, value: await handle(data) });
  } catch (e) {
    postMessage({ id: data.id, ok: false, error: String(e?.message ?? e) });
  } finally {
    // The entropy was used once; do not keep it.
    if (data.entropy) data.entropy.fill(0);
  }
};
