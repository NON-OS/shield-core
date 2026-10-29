import { h } from "../ui/h.js";
import { button } from "../ui/button.js";
import { facts } from "../ui/facts.js";
import { app } from "../state/app.js";
import { inFlight } from "../state/in-flight.js";
import { unanchored } from "../text/unanchored.js";
import { proofProgress } from "../ui/proof-progress.js";
import { begin, finish } from "../state/proof-progress.js";
import { resetMeter } from "../state/net-meter.js";

async function run(p) {
  resetMeter();
  begin({ network: true });
  try {
    const method = p.withdraw ? "withdraw" : "sendPrivate";
    const t = await app.call(method, p.coin, p.to, p.amount, p.early);
    await finish(app.store);
    app.shielded = await app.call("balances").catch(() => app.shielded);
    await inFlight.set(app, { withdraw: p.withdraw, ticket: t });
    app.show("spend", { withdraw: p.withdraw, ticket: t });
  } catch (e) {
    if (e?.kind === "Stopped") return;
    if (e?.kind === "TooSoon") {
      app.show("spend", { ...p, proving: false, running: null, tooSoon: true });
      return;
    }
    app.show("spend", { ...p, proving: false, running: null });
    app.fail(unanchored(e, app.shielded, p.coin, p.amount, app.relayFees?.[p.coin]) ?? e);
  }
}

/** The proof being made here. It cannot be stopped midway, so Cancel ends the worker instead. */
export function proving(p) {
  // A screen is drawn again whenever anything changes, and the proof must start only once.
  p.running ??= run(p);
  const { meter, elapsed } = proofProgress();
  const threads = app.proving?.threads || 1;
  const cancel = async () => {
    await app.wallet.restart();
    app.show("locked");
    app.fail({ kind: "Prove", detail: "Cancelled" });
  };
  return {
    body: [
      h("p", { class: "statement", role: "status" }, "Proving."),
      h(
        "p",
        { class: "lead" },
        `On this device, using ${threads === 1 ? "one thread" : `${threads} threads`}. Nothing has been sent.`,
      ),
      meter,
      facts([
        ["elapsed", elapsed],
        ["circuit", "launch, 19 queries, grind 28"],
      ]),
    ],
    footer: [button("Cancel", cancel, { kind: "outline", busy: "Stopping" })],
  };
}
