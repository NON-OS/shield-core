// NONOS Operating System (AGPL-3.0-or-later)
//
// The browser API for proving a spend on the user's own device.
//
//   import { Prover } from "./nox.js";
//   const prover = await Prover.start({ cacheUrl: "./periodic.top" });
//   const proof = await prover.prove(requestJson, seedJson);   // parsed JSON
//   prover.stop();
//
// The proof runs in a module Web Worker (./nox-worker.js) on every core the
// browser offers, so the page never blocks. Threads need the page served
// cross-origin isolated:
//
//   Cross-Origin-Opener-Policy: same-origin
//   Cross-Origin-Embedder-Policy: require-corp
//
// Without those headers `start` refuses with a message saying so, unless
// `{ singleThread: true }` is passed with a package built by
// `build_web.py --single`. Nothing leaves the machine: the request and the
// seed go to the worker and nowhere else, and the randomness is the
// browser's CSPRNG.

const ENTROPY_BYTES = 512;

export class Prover {
  #worker;
  #next = 1;
  #pending = new Map();

  constructor(worker) {
    this.#worker = worker;
    worker.onmessage = ({ data }) => {
      const p = this.#pending.get(data.id);
      if (!p) return;
      this.#pending.delete(data.id);
      data.ok ? p.resolve(data.value) : p.reject(new Error(data.error));
    };
    worker.onerror = (e) => {
      const err = new Error(`the prover worker failed: ${e.message || e}`);
      for (const p of this.#pending.values()) p.reject(err);
      this.#pending.clear();
    };
  }

  /**
   * Start the worker and its thread pool, and load the periodic cache when a
   * URL is given. The cache is checked on every use, never trusted: a wrong
   * one fails the proof with a reason, it never yields a proof the chain
   * refuses.
   */
  static async start({ workerUrl = new URL("./nox-worker.js", import.meta.url), cacheUrl = null, threads = null, singleThread = false } = {}) {
    if (!singleThread && !globalThis.crossOriginIsolated) {
      throw new Error(
        "this page is not cross-origin isolated, so the browser allows no worker threads: serve it with " +
          "Cross-Origin-Opener-Policy: same-origin and Cross-Origin-Embedder-Policy: require-corp, " +
          "or start with { singleThread: true } and the single-thread package"
      );
    }
    const prover = new Prover(new Worker(workerUrl, { type: "module" }));
    const n = singleThread ? 0 : Math.max(1, threads ?? navigator.hardwareConcurrency ?? 4);
    let cache = null;
    if (cacheUrl) {
      const r = await fetch(cacheUrl);
      if (!r.ok) throw new Error(`the periodic cache could not be fetched: ${r.status}`);
      cache = new Uint8Array(await r.arrayBuffer());
    }
    await prover.#call("init", { threads: n, cache }, cache ? [cache.buffer] : []);
    return prover;
  }

  /**
   * Prove a spend. `request` and `seed` are the pool's request and the
   * owner's seed file, as strings or objects. Resolves to the proof as
   * parsed JSON; it holds the spender's new note secrets, so store it as a
   * secret and drop it when stored.
   */
  async prove(request, seed) {
    const text = (v) => (typeof v === "string" ? v : JSON.stringify(v));
    const entropy = crypto.getRandomValues(new Uint8Array(ENTROPY_BYTES));
    const json = await this.#call("prove", { request: text(request), seed: text(seed), entropy }, [entropy.buffer]);
    return JSON.parse(json);
  }

  stop() {
    this.#worker.terminate();
    const err = new Error("the prover was stopped");
    for (const p of this.#pending.values()) p.reject(err);
    this.#pending.clear();
  }

  #call(op, args, transfer) {
    const id = this.#next++;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      this.#worker.postMessage({ id, op, ...args }, transfer);
    });
  }
}
