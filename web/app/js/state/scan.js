// The apps' read of the pool every five minutes or so, give or take one, while the wallet is open
// and nothing else runs. It runs only while this page is open: a closed page reads nothing, and
// the next open reads the pool when the shield is shown.

import { app } from "./app.js";

const PERIOD = 300;
const JITTER = 60;
const unlockedScreens = new Set(["overview", "shield", "receive", "accounts", "settings"]);

export function watchScan() {
  const next = () => setTimeout(tick, (PERIOD + JITTER * (2 * Math.random() - 1)) * 1000);
  const tick = async () => {
    if (unlockedScreens.has(app.screen) && !app.wallet?.busy() && !app.offline) {
      if (await app.call("networkHasShield", app.network).catch(() => false)) {
        const chain = await app.call("syncChain").catch(() => null);
        if (chain) {
          app.chain = chain;
          app.shielded = chain.balances;
        }
      }
      app.public = (await app.call("publicBalances", app.network).catch(() => null)) ?? app.public;
      app.draw();
    }
    next();
  };
  next();
}
