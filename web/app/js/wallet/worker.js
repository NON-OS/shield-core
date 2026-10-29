// The wallet's worker. It holds the native core, loads the stored files into it before the first
// call and stores what each call changed. The core blocks here on its requests and on the proof,
// which a page's main thread may not do, so the page talks to it only through messages.
//
// The core sends each request with the browser's synchronous XMLHttpRequest. Here that name is
// the stand-in that hands the request to the page, which carries it through the mixnet, so the
// core's transport is unchanged and no request leaves this worker by itself.

import init, * as core from "../../pkg/nox_shield_web.js";
import { openStore } from "./store.js";
import { syncRequest } from "./sync-request.js";
import { startGpuGrind } from "./grind/client.js";

const DIR = "/shield";
let wallet = null;
let store = null;
let memory = null;
let cache = null;
let requests = null;
let grind = null;

// The prover names each phase as it finishes, from inside the call that holds this thread. Posting
// is not held up by that call, so the page sees the proof move while it runs.
self.shieldPhase = (phase, done) => postMessage({ phase, done });

const unhex = (h) => Uint8Array.from(h.match(/../g) ?? [], (b) => parseInt(b, 16));

async function persist() {
  const changes = JSON.parse(core.changed_files()).map(({ path, bytes }) => ({
    path,
    bytes: bytes && unhex(bytes),
  }));
  await store.apply(changes);
}

async function start({ threads, cache: top, port, gpu, big }) {
  requests = syncRequest(port, XMLHttpRequest);
  self.XMLHttpRequest = requests.Request;
  memory = (await init()).memory;
  cache = top;
  if (threads > 0) await core.initThreadPool(threads);
  // The grind on the GPU where it is faster and agrees with the cores; the cores otherwise.
  grind =
    threads > 0 && gpu !== "off"
      ? await startGpuGrind({ core, threads, force: gpu === "force", big }).catch(() => null)
      : null;
  store = await openStore();
  for (const [path, bytes] of await store.files()) core.load_file(path, bytes);
  // The periodic cache is the same for every wallet. It is loaded, never stored, so storage holds
  // only what is this wallet's own.
  if (cache) core.load_file(`${DIR}/periodic-${core.periodic_root().slice(0, 8)}.top`, cache);
  wallet = new core.WebWallet(DIR);
  return wallet.call("stored", []);
}

// One proof of the pinned test vector, whose notes are fixtures under a root no pool knows, so it
// spends nothing. The prover checks the proof before returning it, so finishing is the result.
async function time() {
  const text = async (name) => (await fetch(`../../prover/vector/${name}`)).text();
  const [request, seed, entropy] = await Promise.all(
    ["request.json", "seed.json", "entropy.hex"].map(text),
  );
  const start = performance.now();
  const proved = core.prove_reporting(request, seed, unhex(entropy.trim()), cache);
  const seconds = (performance.now() - start) / 1000;
  const { point, proof, proof_bytes: proofBytes } = JSON.parse(proved);
  // The public words pass 2^53, so they are kept as the prover wrote them.
  const publics =
    proved
      .match(/"publics": \[([^\]]*)\]/)?.[1]
      .split(", ")
      .filter(Boolean) ?? [];
  return JSON.stringify({
    seconds,
    gpu: Boolean(grind),
    gpuCommit: Boolean(grind?.committing),
    gpuBig: Boolean(grind?.big),
    wasmBytes: memory.buffer.byteLength,
    point,
    proof,
    proofBytes,
    publics,
  });
}

async function call({ method, args }) {
  requests.next();
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
      case "time":
        reply({ ok: await time() });
        break;
      case "searchStart":
        requests.next();
        wallet.search_start();
        reply({ ok: "null" });
        break;
      case "searchProgress": {
        // The search writes the accounts it keeps as it ends, so storing follows its result.
        const found = wallet.search_result();
        if (found !== undefined && found !== null) await persist();
        reply({
          ok: JSON.stringify({ looked: wallet.search_progress(), found: found ?? null }),
        });
        break;
      }
      case "readFile": {
        const bytes = core.read_file(data.path);
        reply({ ok: bytes ? JSON.stringify(Array.from(bytes)) : "null" });
        break;
      }
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
