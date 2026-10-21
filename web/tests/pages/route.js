// Times the wallet's reads through the route the page uses, for web/tests/nym.mjs: the real core
// in its worker, the real bridge and tunnel, with Nym on and with Nym off in turn, one read after
// the other so both meet the same network. Served beside a release's files, so its imports are
// the release's own. The passkey's secret is fixed test bytes; the wallet is made for the run.

import { Wallet } from "./js/wallet/client.js";
import { Tunnel } from "./js/route/tunnel.js";
import { bridge } from "./js/route/bridge.js";
import { route } from "./js/state/route.js";

const reads = Number(new URLSearchParams(location.search).get("reads") ?? 20);
const tunnel = new Tunnel(new URL("./js/route/worker.js", import.meta.url));
const wallet = new Wallet(
  new URL("./js/wallet/worker.js", import.meta.url),
  bridge(tunnel, () => {}),
);

async function timed(nym, method, ...args) {
  route.nym = nym;
  const started = performance.now();
  const ok = await wallet.call(method, ...args).then(
    () => true,
    () => false,
  );
  return { route: nym ? "nym" : "direct", method, ok, ms: performance.now() - started };
}

async function run() {
  await wallet.start({ threads: 0, cache: new Uint8Array() });
  await wallet.holdKey(new Uint8Array(32).fill(7));
  await wallet.call("create");
  const runs = [{ ...(await timed(true, "publicBalances", "sepolia")), cold: true }];
  for (let i = 0; i < reads; i++) {
    runs.push(await timed(true, "publicBalances", "sepolia"));
    runs.push(await timed(false, "publicBalances", "sepolia"));
  }
  runs.push(await timed(true, "syncChain"));
  runs.push(await timed(false, "syncChain"));
  return { runs, gateway: route.gateway };
}

run().then(
  (r) => (window.result = { ok: true, ...r }),
  (e) => (window.result = { ok: false, error: String(e?.message ?? e) }),
);
