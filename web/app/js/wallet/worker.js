// The wallet's worker. It holds the native core, loads the stored files into it before the first
// call and stores what each call changed. The core blocks here on its requests and on the proof,
// which a page's main thread may not do, so the page talks to it only through messages.

import init, * as core from "../../pkg/nox_shield_web.js";
import { openStore } from "./store.js";

const DIR = "/shield";
let wallet = null;
let store = null;

const unhex = (h) => Uint8Array.from(h.match(/../g) ?? [], (b) => parseInt(b, 16));

async function persist() {
  const changes = JSON.parse(core.changed_files()).map(({ path, bytes }) => ({
    path,
    bytes: bytes && unhex(bytes),
  }));
  await store.apply(changes);
}

async function start({ threads, cache }) {
  await init();
  if (threads > 0) await core.initThreadPool(threads);
  store = await openStore();
  for (const [path, bytes] of await store.files()) core.load_file(path, bytes);
  // The periodic cache is the same for every wallet. It is loaded, never stored, so storage holds
  // only what is this wallet's own.
  if (cache) core.load_file(`${DIR}/periodic-${core.periodic_root().slice(0, 8)}.top`, cache);
  wallet = new core.WebWallet(DIR);
  return wallet.call("stored", []);
}

async function call({ method, args }) {
  try {
    return { ok: wallet.call(method, args.map(String)) };
  } catch (e) {
    return { failure: typeof e === "string" ? e : String(e?.message ?? e) };
  } finally {
    await persist();
  }
}

onmessage = async ({ data }) => {
  const reply = (body) => postMessage({ id: data.id, ...body });
  try {
    switch (data.op) {
      case "start":
        reply({ ok: await start(data) });
        break;
      case "key":
        reply({ ok: String(wallet.hold_key(data.secret)) });
        data.secret.fill(0);
        break;
      case "call":
        reply(await call(data));
        break;
      default:
        reply({
          failure: JSON.stringify({ kind: "Unknown", detail: data.op, text: "unknown operation" }),
        });
    }
  } catch (e) {
    reply({
      failure: JSON.stringify({ kind: "Worker", detail: "", text: String(e?.message ?? e) }),
    });
  }
};
