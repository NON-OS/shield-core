import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { button } from "../ui/button.js";
import { app } from "../state/app.js";
import { short } from "../text/short.js";

const coins = [
  ["ETH", "eth"],
  ["NOX", "nox"],
  ["USDC", "usdc"],
];

async function read() {
  const balances = await app.run(() => app.call("publicBalances", app.network));
  if (balances) {
    app.public = balances;
    app.draw();
  }
}

export function overview() {
  const held = app.public?.network === app.network ? app.public : null;
  const account = app.accounts?.find((a) => a.active);
  const choose = h(
    "select",
    { id: "network", "aria-label": "Network" },
    h("option", { value: "sepolia" }, "Sepolia, test network"),
    h("option", { value: "mainnet" }, "Ethereum, real money"),
  );
  choose.value = app.network;
  choose.addEventListener("change", async () => {
    app.network = choose.value;
    await app.store.setMeta("network", app.network);
    app.public = null;
    app.draw();
  });
  return frame(
    "03",
    "Wallet",
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
        { type: "button", class: "icon-button", onclick: () => app.show("settings") },
        "Settings",
      ),
    ),
    h(
      "div",
      { class: "pills" },
      h(
        "button",
        { type: "button", class: "icon-button", onclick: () => app.show("accounts") },
        `Account ${(account?.index ?? 0) + 1}  ${short(account?.publicAddress ?? "")}`,
      ),
      h("div", { class: "field" }, choose),
    ),
    h(
      "section",
      { class: "tile", "aria-label": "Public balances" },
      coins.map(([label, key]) =>
        h(
          "div",
          { class: "balance" },
          h("span", {}, label),
          h("span", { class: "amount" }, held ? held[key] : "–"),
        ),
      ),
      h("p", { class: "muted" }, held ? "Read from a public endpoint" : "Not read yet"),
      button("Read again", read, { kind: "outline", busy: "Reading" }),
    ),
    h(
      "nav",
      { class: "round", "aria-label": "Actions" },
      button("Send", () => app.show("accountSend")),
      button("Receive", async () =>
        app.show((await app.call("networkHasShield", app.network)) ? "receive" : "accountReceive"),
      ),
      button("Shield", () => app.show("shield")),
    ),
  );
}

/** Read the accounts once, so the pill can name the one in use. */
overview.enter = async () => {
  app.accounts = await app.call("accounts").catch(() => app.accounts);
};
