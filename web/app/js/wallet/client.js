// The page's side of the wallet worker: each call a promise of its parsed answer, or of a
// WalletFailure naming the stage that refused.

import { WalletFailure } from "./failure.js";

export class Wallet {
  #worker;
  #next = 1;
  #waiting = new Map();
  #url;
  #options;

  constructor(url) {
    this.#url = url;
  }

  #spawn() {
    this.#worker = new Worker(this.#url, { type: "module" });
    this.#worker.onmessage = ({ data }) => {
      const p = this.#waiting.get(data.id);
      if (!p) return;
      this.#waiting.delete(data.id);
      if ("ok" in data) p.resolve(data.ok === undefined ? null : JSON.parse(data.ok));
      else p.reject(new WalletFailure(JSON.parse(data.failure)));
    };
  }

  #send(message, transfer = []) {
    const id = this.#next++;
    return new Promise((resolve, reject) => {
      this.#waiting.set(id, { resolve, reject });
      this.#worker.postMessage({ id, ...message }, transfer);
    });
  }

  /** Start the worker with the shipped periodic cache. Resolves to whether a wallet is stored. */
  async start({ threads, cache }) {
    this.#options = { threads, cache };
    this.#spawn();
    return this.#send({ op: "start", threads, cache: cache.slice() });
  }

  /** Give the core the passkey's secret for the next create, restore or unlock. */
  async holdKey(secret) {
    return this.#send({ op: "key", secret }, [secret.buffer]);
  }

  /** Time one proof of the pinned test vector on this device. */
  time() {
    return this.#send({ op: "time" });
  }

  call(method, ...args) {
    return this.#send({ op: "call", method, args });
  }

  /**
   * Stop whatever runs, a proof above all, by ending the worker and starting a new one. Nothing a
   * call had not finished was stored, so nothing half done survives and nothing was sent.
   */
  async restart() {
    this.#worker.terminate();
    const stopped = new WalletFailure({ kind: "Stopped", detail: "", text: "stopped" });
    for (const p of this.#waiting.values()) p.reject(stopped);
    this.#waiting.clear();
    this.#spawn();
    return this.#send({ op: "start", ...this.#options, cache: this.#options.cache.slice() });
  }
}
