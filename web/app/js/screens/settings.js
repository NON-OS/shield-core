import { frame } from "../ui/frame.js";
import { facts } from "../ui/facts.js";
import { quiet } from "../ui/quiet.js";
import { app } from "../state/app.js";
import { watchIdle } from "../state/idle.js";
import { watchInstall } from "../state/install.js";
import { credits } from "./credits.js";
import { storage } from "../device/storage.js";

const proofText = {
  ready: (p) =>
    p.measured ? `ready, a test proof took ${Math.round(p.measured.seconds)} s` : "ready",
  unmeasured: () => "not timed on this device yet",
  stopped: () => "this device could not finish a test proof",
  unable: () => "this browser cannot run the prover",
};

export function settings() {
  const p = app.proving;
  const idle = watchIdle.options.find(([s]) => s === app.idle)?.[1] ?? "after five minutes";
  const installed = watchInstall.installed();
  return frame(
    { number: "04", title: "Settings", backdrop: "settings", back: () => app.show("overview") },
    facts([
      ["app", app.version],
      ["key held in", "a passkey"],
      ["released", "after you are confirmed"],
      ["route", "browser, direct"],
      ["lander", "none, you settle each spend"],
      ["private sends", (proofText[p?.state] ?? proofText.unable)(p ?? {})],
      ["threads", p?.threads ? String(p.threads) : "one, the page is not isolated"],
      ["storage", app.storageKept ? "kept by the browser" : "may be cleared by the browser"],
    ]),
    quiet([
      ["Recovery words and keys", () => app.show("keys")],
      [
        "Lock now",
        () =>
          app.run(async () => {
            await app.call("lock");
            app.show("locked");
          }),
      ],
      [`Lock when idle: ${idle}`, () => watchIdle.cycle()],
      !installed && app.install && ["Add to the home screen", () => app.install()],
      !installed && !app.install && ["Add to the home screen", () => app.show("install")],
      ["What the web version trusts", () => app.show("warning", { back: "settings" })],
      ["Check this release", () => app.show("release")],
      ["Licences", () => app.show("licences")],
      ["Destroy this wallet", () => app.show("wipe", { back: "settings" })],
    ]),
    credits(),
  );
}

settings.enter = async () => {
  app.storageKept = await storage.kept();
};
