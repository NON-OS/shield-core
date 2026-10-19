import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { facts } from "../ui/facts.js";
import { app } from "../state/app.js";

const proofText = {
  ready: (p) =>
    p.measured ? `ready, a test proof took ${Math.round(p.measured.seconds)} s` : "ready",
  unmeasured: () => "not yet timed on this device",
  stopped: () => "this device could not finish a test proof",
  unable: () => "this browser cannot run the prover",
};

export function settings() {
  const link = (label, to, params) =>
    h("button", { type: "button", class: "link", onclick: () => app.show(to, params) }, label);
  const p = app.proving;
  return frame(
    "04",
    "Settings",
    facts([
      ["release", app.version],
      ["key held in", "a passkey"],
      ["released", "after you are verified"],
      ["route", "browser, direct, no Tor"],
      ["lander", "none, you settle each spend"],
      ["private sends", (proofText[p?.state] ?? proofText.unable)(p ?? {})],
      ["threads", p?.threads ? String(p.threads) : "one, the page is not isolated"],
    ]),
    h(
      "nav",
      { class: "actions", "aria-label": "Settings" },
      link("Recovery words and keys", "keys"),
      h(
        "button",
        {
          type: "button",
          class: "link",
          onclick: () =>
            app.run(async () => {
              await app.call("lock");
              app.show("locked");
            }),
        },
        "Lock now",
      ),
      link("Time a proof in this browser", "measure"),
      link("What this page trusts", "warning", { back: "settings" }),
      link("Check this release", "release"),
      link("Licences", "licences"),
      link("Destroy this wallet", "wipe", { back: "settings" }),
      link("Back", "overview"),
    ),
    h(
      "section",
      { class: "tile", "aria-label": "About" },
      h(
        "p",
        {},
        "NØNOS Wallet: private payments on Ethereum. NOX is the token; NOX Shield is the private layer.",
      ),
      h("p", { class: "muted" }, "Designed after Etna, the volcano of Sicily, where NØNOS began."),
    ),
  );
}
