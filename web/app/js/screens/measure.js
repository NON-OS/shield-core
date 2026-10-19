import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { button } from "../ui/button.js";
import { facts } from "../ui/facts.js";
import { app } from "../state/app.js";
import { proving } from "../device/proving.js";

/**
 * One proof of the pinned test vector, timed. It spends nothing. On a phone this is what lets
 * private sends through: if the browser ends the page instead, the mark set before the proof
 * stays, and the next visit knows this device cannot prove.
 */
export function measure() {
  const p = app.params;
  const run = () =>
    app.run(async () => {
      await proving.started(app.store);
      app.show("measure", { running: true });
      const result = await app.wallet.time();
      await proving.finished(app.store, { ...result, at: Date.now() });
      app.proving = await proving(app.store);
      app.show("measure", { result });
    });
  return frame(
    "05",
    "Time a proof",
    p.result
      ? [
          h("p", { class: "statement", role: "status" }, "This device can prove."),
          facts([
            ["proof", `${Math.round(p.result.seconds)} s`],
            ["memory", `${Math.round(p.result.wasmBytes / 2 ** 20)} MiB`],
            ["threads", String(app.proving?.threads || 1)],
          ]),
        ]
      : p.running
        ? [
            h("p", { class: "statement", role: "status" }, "Proving the test vector."),
            h(
              "p",
              { class: "lead" },
              "This takes a few minutes. Keep the page open. If it reloads, this device cannot hold a proof.",
            ),
            h("div", { class: "progress", "aria-hidden": "true" }, h("span")),
          ]
        : [
            h(
              "p",
              { class: "lead" },
              "One proof of a fixed test spend, whose notes exist in no pool, so nothing is spent or sent. It shows how long a private send takes here, and whether this browser can hold one.",
            ),
            h("div", { class: "actions" }, button("Time one proof", run)),
          ],
    !p.running &&
      h("button", { type: "button", class: "link", onclick: () => app.show("settings") }, "Back"),
  );
}
