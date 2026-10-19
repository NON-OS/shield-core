import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { button } from "../ui/button.js";
import { facts } from "../ui/facts.js";
import { meter } from "../ui/meter.js";
import { networkBanner } from "../ui/network-banner.js";
import { app } from "../state/app.js";

function caption(balances) {
  const pending = balances.find((b) => b.pending > 0);
  if (pending) return `${pending.pendingText} ${pending.coin.toUpperCase()} in flight`;
  if (!app.chain) return "Not read from the pool yet";
  if (app.chain.received === 0 && app.chain.deposited === 0)
    return "Nothing received at this address yet";
  if (balances.every((b) => b.spendable === 0)) return "Every note found here has been spent";
  return "Shielded, in this browser";
}

async function sync() {
  const chain = await app.run(() => app.call("syncChain"));
  if (!chain) return;
  app.chain = chain;
  app.shielded = chain.balances;
  app.draw();
}

export function shield() {
  if (app.network !== "sepolia") {
    return frame(
      "03",
      "Shield",
      networkBanner(app.network),
      h("p", { class: "statement" }, "The shield runs on Sepolia until its audit."),
      h(
        "div",
        { class: "actions" },
        button("Switch to Sepolia", async () => {
          app.network = "sepolia";
          await app.store.setMeta("network", "sepolia");
          app.show("shield");
        }),
        button("Back", () => app.show("overview"), { kind: "outline" }),
      ),
    );
  }
  const balances = app.shielded ?? [];
  const spendable = balances.some((b) => b.spendable > 0);
  return frame(
    "03",
    "Shield",
    networkBanner("sepolia"),
    h(
      "section",
      { class: "tile", "aria-label": "Shielded balances" },
      ["nox", "eth"].map((coin) => {
        const b = balances.find((x) => x.coin === coin);
        return h(
          "div",
          { class: "balance" },
          h("span", {}, coin.toUpperCase()),
          h("span", { class: "amount" }, b ? b.spendableText : "–"),
        );
      }),
      h("p", { class: "muted" }, caption(balances)),
    ),
    spendable && meter(app.chain),
    h(
      "nav",
      { class: "round", "aria-label": "Shield actions" },
      button("Deposit", () => app.show("deposit")),
      button("Receive", () => app.show("receive")),
      button("Send", () => app.show("spend", { withdraw: false })),
      button("Withdraw", () => app.show("spend", { withdraw: true })),
    ),
    h(
      "div",
      { class: "actions" },
      button("Read the pool", sync, { kind: "outline", busy: "Reading the pool" }),
      balances.some((b) => b.pending > 0) &&
        button(
          "Take back what was never settled",
          () =>
            app.run(async () => {
              await app.call("takeBackPending");
              await sync();
            }),
          { kind: "outline", busy: "Taking back" },
        ),
    ),
    app.chain &&
      facts([
        ["pool read at block", String(app.chain.head)],
        ["notes held", String(balances.reduce((n, b) => n + b.noteCount, 0))],
        ["key held in", "a passkey"],
      ]),
    h("button", { type: "button", class: "link", onclick: () => app.show("overview") }, "Back"),
  );
}

/** The balances last stored, before the pool is read again. */
shield.enter = async () => {
  app.shielded = await app.call("balances").catch(() => app.shielded);
};
