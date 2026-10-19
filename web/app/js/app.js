// The page's start: check what this browser can do, start the wallet's worker with the shipped
// periodic cache, and show the first screen. Nothing here reaches the network but this site.

import { app } from "./state/app.js";
import { screens } from "./screens/index.js";
import { openStore } from "./wallet/store.js";
import { Wallet } from "./wallet/client.js";
import { proving } from "./device/proving.js";
import { loadCache } from "./release/cache.js";

const root = document.querySelector("main");

app.draw = async () => {
  const screen = screens[app.screen] ?? screens.opening;
  const name = app.screen;
  if (screen.enter && !app.params.entered) {
    app.params.entered = true;
    await screen.enter();
    if (app.screen !== name) return;
  }
  root.replaceChildren(...screen().flat(Infinity).filter(Boolean));
  document.title = `${root.querySelector("h1")?.textContent ?? "NØNOS"} · NØNOS Wallet`;
  root.querySelector("h1")?.focus();
};

async function boot() {
  app.draw();
  if ("serviceWorker" in navigator)
    navigator.serviceWorker.register("sw.js").catch(() => undefined);
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
  app.wallet = new Wallet(new URL("./wallet/worker.js", import.meta.url));
  const stored = await app.wallet.start({
    threads: app.proving.threads,
    cache: cache ?? new Uint8Array(),
  });
  const next = stored ? "locked" : "welcome";
  if (!(await app.store.meta("warned"))) return app.show("warning", { back: next });
  app.show(next);
}

boot().catch((e) => app.fail(e));
