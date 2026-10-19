import { h } from "../ui/h.js";
import { button } from "../ui/button.js";
import { facts } from "../ui/facts.js";
import { app } from "../state/app.js";
import { inFlight } from "../state/in-flight.js";

async function run(p) {
  try {
    const method = p.withdraw ? "withdraw" : "sendPrivate";
    const t = await app.call(method, p.coin, p.to, p.amount, p.early);
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
    app.fail(e);
  }
}

/** The proof being made here. It cannot be stopped midway, so Cancel ends the worker instead. */
export function proving(p) {
  // A screen is drawn again whenever anything changes, and the proof must start only once.
  p.startedAt ??= Date.now();
  p.running ??= run(p);
  const seconds = () => `${Math.round((Date.now() - p.startedAt) / 1000)} s`;
  const elapsed = h("span", {}, seconds());
  const tick = setInterval(() => {
    if (!elapsed.isConnected) return clearInterval(tick);
    elapsed.textContent = seconds();
  }, 1000);
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
      h("div", { class: "progress", "aria-hidden": "true" }, h("span")),
      facts([
        ["elapsed", elapsed],
        ["circuit", "launch, 19 queries, grind 28"],
      ]),
    ],
    footer: [button("Cancel", cancel, { kind: "outline", busy: "Stopping" })],
  };
}
