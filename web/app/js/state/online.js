// Whether the browser says it has a network. Offline the shell still opens; anything that reads
// the chain says it needs one.

import { app } from "./app.js";

export function watchOnline() {
  app.offline = !navigator.onLine;
  const set = (offline) => {
    app.offline = offline;
    app.draw();
  };
  addEventListener("online", () => set(false));
  addEventListener("offline", () => set(true));
}
