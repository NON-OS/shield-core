// Locking when nobody is there, as the apps do: after the chosen time without a touch or a key,
// checked every five seconds, and at once when the page is hidden. A proof in progress is left
// to finish, since a hidden tab on a computer is where one often runs.

import { app } from "./app.js";

const IDLE = [
  [0, "immediately"],
  [60, "after a minute"],
  [300, "after five minutes"],
  [-1, "never"],
];
const DEFAULT = 300;
const CHECK = 5000;
const unlockedScreens = new Set([
  "overview",
  "accountSend",
  "accountReceive",
  "shield",
  "deposit",
  "receive",
  "spend",
  "settings",
  "keys",
  "accounts",
  "measure",
  "licences",
  "release",
]);

let touched = Date.now();

async function lock() {
  if (app.params.proving || app.params.running) return;
  await app.call("lock").catch(() => undefined);
  app.public = app.shielded = app.chain = null;
  app.show("locked");
}

export async function watchIdle() {
  app.idle = (await app.store.meta("lock-idle")) ?? DEFAULT;
  const touch = () => (touched = Date.now());
  for (const kind of ["pointerdown", "keydown", "wheel"])
    addEventListener(kind, touch, { passive: true });
  setInterval(() => {
    if (app.idle < 0 || !unlockedScreens.has(app.screen) || app.wallet?.busy()) return;
    if ((Date.now() - touched) / 1000 >= app.idle) lock();
  }, CHECK);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState !== "hidden") return;
    if (app.screen === "phrase") {
      app.params.words?.fill("");
      lock();
    } else if (app.screen === "restore" || app.screen === "finding") app.show("welcome");
    else if (unlockedScreens.has(app.screen)) lock();
  });
}

watchIdle.options = IDLE;

/** The next choice in the list, as the Android setting cycles, kept for the next visit. */
watchIdle.cycle = async () => {
  const at = IDLE.findIndex(([s]) => s === app.idle);
  app.idle = IDLE[(at + 1) % IDLE.length][0];
  touched = Date.now();
  await app.store.setMeta("lock-idle", app.idle);
  app.draw();
};
