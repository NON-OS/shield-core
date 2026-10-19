// The page's handle on the mixnet's worker: one tunnel through one pinned gateway, started on the
// first request. A tunnel that fails is ended, and the next start takes the next gateway in a
// rotation that begins at a random one, so the users of a release spread over the set.
//
// Each tunnel is a new Nym client under a name of its own, so two sessions share no Nym identity
// and no gateway registration. Its storage is deleted when the tunnel ends, and on the next start
// whatever an ended page left behind.

import { route } from "../state/route.js";

const SETUP_MS = 60_000;
const FETCH_MS = 90_000;
const PREFIX = "wasm-client-storage-shield-";

const hex = (n) =>
  [...crypto.getRandomValues(new Uint8Array(n))]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

async function forget(name) {
  const names = name
    ? [name]
    : ((await indexedDB.databases?.()) ?? [])
        .map((d) => d.name)
        .filter((n) => n?.startsWith(PREFIX));
  for (const n of names) indexedDB.deleteDatabase(n);
}

export class Tunnel {
  #url;
  #gateways;
  #turn;
  #worker = null;
  #client = "";
  #ready = null;
  #next = 1;
  #waiting = new Map();
  #fresh = true;
  #epoch = 0;

  constructor(url, gateways) {
    this.#url = url;
    this.#gateways = gateways;
    this.#turn = crypto.getRandomValues(new Uint32Array(1))[0] % gateways.length;
  }

  #ask(message, ms) {
    const id = this.#next++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#waiting.delete(id);
        reject(new Error("the mixnet did not answer in time"));
      }, ms);
      this.#waiting.set(id, { resolve, reject, timer });
      this.#worker.postMessage({ id, ...message });
    });
  }

  #spawn() {
    this.#worker = new Worker(this.#url, { type: "module" });
    this.#worker.onmessage = ({ data }) => {
      const p = this.#waiting.get(data.id);
      if (!p) return;
      this.#waiting.delete(data.id);
      clearTimeout(p.timer);
      if ("failure" in data) p.reject(new Error(data.failure));
      else p.resolve(data);
    };
    this.#worker.onerror = (e) => this.#drop(new Error(e.message || "the mixnet's worker stopped"));
  }

  #drop(error) {
    for (const p of this.#waiting.values()) {
      clearTimeout(p.timer);
      p.reject(error);
    }
    this.#waiting.clear();
  }

  /** The tunnel, started if it is not. */
  ready() {
    if (!this.#ready) {
      const gateway = this.#gateways[this.#turn % this.#gateways.length];
      route.tunnel = "connecting";
      route.gateway = gateway.host;
      this.#ready = this.#start(gateway, this.#epoch);
    }
    return this.#ready;
  }

  async #start(gateway, epoch) {
    if (this.#fresh) await forget();
    this.#fresh = false;
    // A stop while the old storage was being deleted ends this start before it has a worker.
    if (epoch !== this.#epoch) throw new Error("the tunnel was ended");
    this.#client = `shield-${hex(8)}`;
    this.#spawn();
    await this.#ask({ op: "setup", gateway: gateway.id, clientId: this.#client }, SETUP_MS);
    route.tunnel = "ready";
  }

  /** One request through the tunnel: its status and body, or a refusal of what failed. */
  async fetch(request) {
    await this.ready();
    return this.#ask({ op: "fetch", ...request }, FETCH_MS);
  }

  /** End this tunnel after a failure; the next request starts one through the next gateway. */
  reset() {
    this.stop();
    this.#turn += 1;
    route.tunnel = "unreachable";
  }

  /** End the tunnel and its traffic, as when Nym is turned off. */
  stop() {
    this.#epoch += 1;
    this.#worker?.terminate();
    this.#drop(new Error("the tunnel was ended"));
    if (this.#client) forget(`wasm-client-storage-${this.#client}`);
    this.#worker = null;
    this.#client = "";
    this.#ready = null;
    route.tunnel = "idle";
  }
}
