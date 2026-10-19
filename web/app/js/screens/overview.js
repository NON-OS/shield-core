import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { avatar } from "../ui/avatar.js";
import { coinRow } from "../ui/coin-row.js";
import { quiet } from "../ui/quiet.js";
import { roundAction } from "../ui/round-action.js";
import { svg } from "../ui/svg.js";
import { app } from "../state/app.js";
import { depositReminder } from "../ui/deposit-reminder.js";
import { readDepositNotes } from "../state/deposit-notes.js";
import { short } from "../text/short.js";

async function read() {
  const balances = await app.run(() => app.call("publicBalances", app.network));
  if (balances) {
    app.public = balances;
    app.draw();
  }
}

const gear = () =>
  svg(22, 22, [
    [
      "circle",
      { cx: "11", cy: "11", r: "3.2", fill: "none", stroke: "currentColor", "stroke-width": "1.8" },
    ],
    [
      "path",
      {
        d: "M11 2.5v2.6M11 16.9v2.6M2.5 11h2.6M16.9 11h2.6M5 5l1.8 1.8M15.2 15.2 17 17M5 17l1.8-1.8M15.2 6.8 17 5",
        fill: "none",
        stroke: "currentColor",
        "stroke-width": "1.8",
        "stroke-linecap": "round",
      },
    ],
  ]);

export function overview() {
  const held = app.public?.network === app.network ? app.public : null;
  const account = app.accounts?.find((a) => a.active);
  const address = account?.publicAddress ?? "";
  const choose = h(
    "select",
    { id: "network", "aria-label": "Network" },
    h("option", { value: "sepolia" }, "Sepolia"),
    h("option", { value: "mainnet" }, "Ethereum"),
  );
  choose.value = app.network;
  choose.addEventListener("change", async () => {
    app.network = choose.value;
    await app.store.setMeta("network", app.network);
    app.public = null;
    app.draw();
    read();
  });
  const note = held ? "Read from a public endpoint" : "Not read yet";
  return frame(
    { number: "03", title: "Wallet", backdrop: "home" },
    h(
      "div",
      { class: "top" },
      h("img", {
        class: "wordmark",
        src: new URL("../../images/wordmark.svg", import.meta.url).href,
        alt: "NØNOS",
      }),
      h(
        "button",
        {
          type: "button",
          class: "gear",
          "aria-label": "Settings",
          onclick: () => app.show("settings"),
        },
        gear(),
      ),
    ),
    h(
      "div",
      { class: "pills" },
      h(
        "button",
        { type: "button", class: "pill", onclick: () => app.show("accounts") },
        address && avatar(address),
        `Account ${(account?.index ?? 0) + 1}  ${short(address)}`,
      ),
      h("label", { class: "pill" }, choose),
    ),
    h(
      "section",
      { class: "tile", "aria-label": "Public balances" },
      coinRow("eth", held ? held.eth : "·", note),
      coinRow("nox", held ? held.nox : "·"),
      coinRow("usdc", held ? held.usdc : "·"),
    ),
    h(
      "nav",
      { class: "round", "aria-label": "Actions" },
      roundAction("Send", "up", () => app.show("accountSend")),
      roundAction("Receive", "down", async () =>
        app.show((await app.call("networkHasShield", app.network)) ? "receive" : "accountReceive"),
      ),
      roundAction("Swap", "swap", () => app.show("swap")),
      roundAction("Shield", "shield", () => app.show("shield")),
    ),
    depositReminder(app),
    quiet([["Read again", read]]),
  );
}

/** Read the accounts once, so the pill can name the one in use. */
overview.enter = async () => {
  app.accounts = await app.call("accounts").catch(() => app.accounts);
  await readDepositNotes(app);
};
