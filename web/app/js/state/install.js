// Adding the wallet to the home screen. Chrome and Edge offer their own prompt, which is kept
// until the user asks for it; iOS has none, and the page tells the user where Safari keeps it.

import { app } from "./app.js";

export function watchInstall() {
  addEventListener("beforeinstallprompt", (event) => {
    event.preventDefault();
    app.install = () => event.prompt();
  });
  addEventListener("appinstalled", () => {
    app.install = null;
  });
}

/** Whether the page already runs as an installed app. */
watchInstall.installed = () =>
  matchMedia("(display-mode: standalone)").matches || navigator.standalone === true;
