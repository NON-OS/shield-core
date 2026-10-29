// The page's start: check what this browser can do, start the wallet's worker with the shipped
// periodic cache and the route for its requests, and show the first screen. Nothing here reaches
// the network but this site; the mixnet's tunnel starts with the wallet's first request.

import { app } from "./state/app.js";
import { screens } from "./screens/index.js";
import { openStore } from "./wallet/store.js";
import { Wallet } from "./wallet/client.js";
import { proving } from "./device/proving.js";
import { loadCache } from "./release/cache.js";
import { watchUpdates } from "./state/update.js";
import { watchOnline } from "./state/online.js";
import { watchInstall } from "./state/install.js";
import { watchIdle } from "./state/idle.js";
import { watchScan } from "./state/scan.js";
import { Tunnel } from "./route/tunnel.js";
import { bridge } from "./route/bridge.js";
import { loadPace, mark } from "./state/proof-progress.js";

const root = document.querySelector("main");

app.draw = async () => {
  const screen = screens[app.screen] ?? screens.opening;
  const name = app.screen;
  if (screen.enter && !app.params.entered) {
    app.params.entered = true;
    await screen.enter();
    if (app.screen !== name) return;
  }
  root.replaceChildren(...[screen()].flat(Infinity).filter(Boolean));
  document.title = `${root.querySelector("h1")?.textContent ?? "NØNOS"} · NØNOS`;
  root.querySelector("h1")?.focus();
};

async function boot() {
  app.draw();
  watchOnline();
  watchInstall();
  watchUpdates();
  const release = await (await fetch("release.json")).json();
  const manifest = await (await fetch("release-manifest.json")).json();
  app.version = release.version;
  app.manifestHash = release.manifestHash;
  app.store = await openStore();
  app.network = (await app.store.meta("network")) ?? "sepolia";
  app.proving = await proving(app.store);
  if (!(await screens.welcome.possible())) return app.show("unsupported");
  const cache = await loadCache(manifest.cache);
  app.cacheReady = Boolean(cache);
  app.tunnel = new Tunnel(new URL("./route/worker.js", import.meta.url));
  // Only Settings shows the tunnel's state, and a redraw elsewhere would clear a field being typed.
  const redraw = () => app.screen === "settings" && app.draw();
  app.wallet = new Wallet(
    new URL("./wallet/worker.js", import.meta.url),
    bridge(app.tunnel, redraw),
  );
  app.wallet.onPhase = mark;
  await loadPace(app.store, app.proving.measured);
  const stored = await app.wallet.start({
    threads: app.proving.threads,
    cache: cache ?? new Uint8Array(),
    // ?gpu=off grinds on the cores alone; ?gpu=force uses any GPU, for testing.
    gpu: new URLSearchParams(location.search).get("gpu"),
  });
  watchIdle();
  watchScan();
  const next = stored ? "locked" : "welcome";
  if (!(await app.store.meta("warned"))) return app.show("warning", { back: next });
  app.show(next);
}

boot().catch((e) => app.fail(e));
