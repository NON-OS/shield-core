// The worker of a new release installs beside the old one and waits. This notices it, so the page
// can offer "Update ready"; taking it hands over to the new worker and reloads once it has.

import { app } from "./app.js";

const CHECK_EVERY = 30 * 60 * 1000;

export async function watchUpdates() {
  if (!("serviceWorker" in navigator)) return;
  const reg = await navigator.serviceWorker.register("sw.js").catch(() => null);
  if (!reg) return;
  let taking = false;
  const ready = () => {
    if (reg.waiting && navigator.serviceWorker.controller) {
      app.updateReady = () => {
        taking = true;
        reg.waiting?.postMessage("take-update");
      };
      app.draw();
    }
  };
  reg.addEventListener("updatefound", () => reg.installing?.addEventListener("statechange", ready));
  ready();
  // The first worker also takes control of the page once it is installed; only a release the
  // user chose to take reloads it.
  navigator.serviceWorker.addEventListener("controllerchange", () => {
    if (!taking) return;
    taking = false;
    location.reload();
  });
  setInterval(() => reg.update().catch(() => undefined), CHECK_EVERY);
}
