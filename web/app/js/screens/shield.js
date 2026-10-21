import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { button } from "../ui/button.js";
import { coinRow } from "../ui/coin-row.js";
import { meter } from "../ui/meter.js";
import { quiet } from "../ui/quiet.js";
import { roundAction } from "../ui/round-action.js";
import { app } from "../state/app.js";
import { inFlight } from "../state/in-flight.js";
import { readPool } from "../state/read-pool.js";
import { landing } from "./landing.js";
import { depositReminder } from "../ui/deposit-reminder.js";
import { readDepositNotes } from "../state/deposit-notes.js";

// The line under a coin: what is in flight in that coin, and under the first row what the pool
// read found. A coin's line never speaks for another coin.
function moving(balances, coin) {
  const b = balances.find((x) => x.coin === coin && x.pending > 0);
  return b && `${b.pendingText} ${coin.toUpperCase()} in flight`;
}

function caption(balances) {
  if (!app.chain) return "Not read from the pool yet";
  if (app.chain.received === 0 && app.chain.deposited === 0)
    return "Nothing received at this address yet";
  if (balances.every((b) => b.spendable === 0)) return "Every note found here has been spent";
  return "Shielded, on this device";
}

export async function sync() {
  const chain = await app.run(() => readPool());
  if (!chain) return;
  app.chain = chain;
  app.shielded = chain.balances;
  await readDepositNotes(app);
  app.draw();
}

export function shield() {
  if (app.network !== "sepolia") {
    return frame(
      {
        number: "03",
        title: "Shield",
        backdrop: "deposit",
        back: () => app.show("overview"),
        footer: [
          button("Switch to Sepolia", async () => {
            app.network = "sepolia";
            await app.store.setMeta("network", "sepolia");
            app.show("shield");
          }),
        ],
      },
      h("p", { class: "statement" }, "The shield runs on Sepolia until its audit."),
    );
  }
  const balances = app.shielded ?? [];
  const of = (coin) => balances.find((x) => x.coin === coin)?.spendableText ?? "·";
  const spendable = balances.some((b) => b.spendable > 0);
  const details = app.params.details;
  return frame(
    { number: "03", title: "Shield", backdrop: "deposit", back: () => app.show("overview") },
    h(
      "section",
      { class: "tile", "aria-label": "Shielded balances" },
      coinRow("nox", of("nox"), moving(balances, "nox") ?? caption(balances)),
      coinRow("eth", of("eth"), moving(balances, "eth")),
    ),
    spendable && meter(app.chain),
    depositReminder(app),
    app.spend && landing(app.spend),
    h(
      "nav",
      { class: "round", "aria-label": "Shield actions" },
      roundAction("Deposit", "in", () => app.show("deposit")),
      roundAction("Receive", "down", () => app.show("receive")),
      roundAction("Send", "up", () => app.show("spend", { withdraw: false })),
      roundAction("Withdraw", "out", () => app.show("spend", { withdraw: true })),
    ),
    quiet([
      [
        app.params.syncing ? "Reading the pool" : "Read the pool",
        async () => {
          app.params.syncing = true;
          app.draw();
          await sync();
          app.params.syncing = false;
          app.draw();
        },
      ],
      balances.some((b) => b.pending > 0) && [
        "Take back what was never settled",
        () =>
          app.run(async () => {
            await app.call("takeBackPending");
            await inFlight.clear(app);
            app.spend = null;
            await sync();
          }),
      ],
      ["Time a proof in this browser", () => app.show("measure")],
      [
        details ? "Hide details" : "Details",
        () => app.show("shield", { details: !details, entered: true }),
      ],
    ]),
    details &&
      h(
        "section",
        { class: "tile", "aria-label": "Details" },
        h(
          "div",
          { class: "tile-row" },
          h("span", { class: "name" }, "Pool read at block"),
          h("span", { class: "value" }, app.chain ? String(app.chain.head) : "none yet"),
        ),
        h(
          "div",
          { class: "tile-row" },
          h("span", { class: "name" }, "Notes held"),
          h("span", { class: "value" }, String(balances.reduce((n, b) => n + b.noteCount, 0))),
        ),
        h(
          "div",
          { class: "tile-row" },
          h("span", { class: "name" }, "Key held in"),
          h("span", { class: "value" }, "a passkey"),
        ),
      ),
  );
}

/** The balances last stored, and any spend still to settle, before the pool is read again. */
shield.enter = async () => {
  app.shielded = await app.call("balances").catch(() => app.shielded);
  app.spend = await inFlight.get(app);
  await readDepositNotes(app);
};
