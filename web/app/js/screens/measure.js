import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { button } from "../ui/button.js";
import { facts } from "../ui/facts.js";
import { app } from "../state/app.js";
import { proving } from "../device/proving.js";
import { zip } from "../files/zip.js";
import { save } from "../files/save.js";
import { card } from "../text/card.js";

const unhex = (s) =>
  Uint8Array.from(s.replace(/^0x/, "").match(/../g) ?? [], (b) => parseInt(b, 16));

function exportProof(r) {
  const publics = JSON.stringify({ n_publics: r.publics.length, publics: r.publics });
  save(
    zip([
      ["launch-proof.bin", unhex(r.proof)],
      ["launch-proof.publics.json", new TextEncoder().encode(publics)],
    ]),
    "nonos-launch-proof.zip",
  );
}

async function shareCard(r) {
  const text = card(r, app);
  if (navigator.share) await navigator.share({ text }).catch(() => undefined);
  else await navigator.clipboard.writeText(text);
}

/**
 * One proof of the pinned test vector, timed, as the apps' Measure screen does. It spends
 * nothing. On a phone this is what lets private sends through: if the browser ends the page
 * instead, the mark set before the proof stays, and the next visit knows this device cannot prove.
 */
export function measure() {
  const p = app.params;
  const r = p.result;
  const run = () =>
    app.run(async () => {
      await proving.started(app.store);
      app.show("measure", { running: true });
      const result = await app.wallet.time();
      await proving.finished(app.store, {
        seconds: result.seconds,
        wasmBytes: result.wasmBytes,
        at: Date.now(),
      });
      app.proving = await proving(app.store);
      app.show("measure", { result });
    });
  const threads = app.proving?.threads || 1;
  return frame(
    {
      number: "05",
      title: "Measure",
      backdrop: "proving",
      back: p.running ? null : () => app.show("settings"),
      footer: p.running
        ? []
        : [
            button("Time one proof", run),
            r && button("Export the proof", () => exportProof(r), { kind: "outline" }),
            r && button("Share the card", () => shareCard(r), { kind: "outline" }),
          ].filter(Boolean),
    },
    p.running && [
      h("p", { class: "statement", role: "status" }, "Proving."),
      h(
        "p",
        { class: "lead" },
        `On this device, using ${threads === 1 ? "one thread" : `${threads} threads`}. Nothing has been sent. If the page reloads instead of finishing, this device cannot hold a proof.`,
      ),
      h("div", { class: "progress", "aria-hidden": "true" }, h("span")),
    ],
    r && [
      h("p", { class: "statement", role: "status" }, "A real transfer, proved on this device."),
      h(
        "p",
        { class: "figure" },
        h("span", { class: "number" }, r.seconds.toFixed(1)),
        h("span", { class: "unit" }, "seconds to prove"),
      ),
      facts([
        ["circuit", "launch, the pool's"],
        ["verified here", "inside the time"],
        ["proof", `${r.proofBytes} bytes`],
        ["peak memory", `${Math.round(r.wasmBytes / 2 ** 20)} MiB`],
        ["threads", threads === 1 ? "one" : String(threads)],
        ["queries", `${r.point[0]} at grind ${r.point[1]}`],
      ]),
    ],
    !p.running &&
      !r &&
      h(
        "p",
        { class: "lead" },
        "One proof of a fixed test spend, whose notes exist in no pool, so nothing is spent or sent. It shows how long a private send takes here, and whether this browser can hold one.",
      ),
  );
}
