// The page's side of the wallet worker: each call a promise of its parsed answer, or of a
// WalletFailure naming the stage that refused. Each worker is started with a port of its own for
// the requests the core makes, which `route` answers.

import { WalletFailure } from "./failure.js";

export class Wallet {
  #worker;
  #next = 1;
  #waiting = new Map();
  #url;
  #options;
  #route;
  /** Called with each phase a running proof finishes. */
  onPhase = null;

  constructor(url, route) {
    this.#url = url;
    this.#route = route;
  }

  #spawn() {
    this.#worker = new Worker(this.#url, { type: "module" });
    this.#worker.onmessage = ({ data }) => {
      if ("phase" in data) return this.onPhase?.(data.phase);
      const p = this.#waiting.get(data.id);
      if (!p) return;
      this.#waiting.delete(data.id);
      if ("ok" in data) p.resolve(data.ok === undefined ? null : JSON.parse(data.ok));
      else p.reject(new WalletFailure(JSON.parse(data.failure)));
    };
  }

  #start() {
    const { port1, port2 } = new MessageChannel();
    this.#route(port2);
    const { threads, cache, gpu, big } = this.#options;
    return this.#send({ op: "start", threads, gpu, big, cache: cache.slice(), port: port1 }, [
      port1,
    ]);
  }

  #send(message, transfer = []) {
    const id = this.#next++;
    return new Promise((resolve, reject) => {
      this.#waiting.set(id, { resolve, reject });
      this.#worker.postMessage({ id, ...message }, transfer);
    });
  }

  /** Start the worker with the shipped periodic cache. Resolves to whether a wallet is stored. */
  async start({ threads, cache, gpu, big }) {
    this.#options = { threads, cache, gpu, big };
    this.#spawn();
    return this.#start();
  }

  /** Give the core the passkey's secret for the next create, restore or unlock. */
  async holdKey(secret) {
    return this.#send({ op: "key", secret }, [secret.buffer]);
  }

  /** Time one proof of the pinned test vector on this device. */
  time() {
    return this.#send({ op: "time" });
  }

  /** Start the account search of a restored phrase; `searchProgress` says how far it has got. */
  searchStart() {
    return this.#send({ op: "searchStart" });
  }

  /** How many accounts the search has looked at, and how many it kept once it ends. */
  searchProgress() {
    return this.#send({ op: "searchProgress" });
  }

  /** A file the wallet wrote, as bytes, for a download. */
  async readFile(path) {
    const bytes = await this.#send({ op: "readFile", path });
    return bytes && Uint8Array.from(bytes);
  }

  /** Whether a call is still running, so background work can wait its turn. */
  busy() {
    return this.#waiting.size > 0;
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
    return this.#start();
  }
}
