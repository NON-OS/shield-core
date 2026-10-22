import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { button } from "../ui/button.js";
import { coinRow } from "../ui/coin-row.js";
import { networkBanner } from "../ui/network-banner.js";
import { app } from "../state/app.js";
import { confirmed } from "../device/confirmed.js";
import { swapTerms } from "./swap-terms.js";
import { swapSent } from "./swap-sent.js";

const coins = [
  ["eth", "ETH"],
  ["nox", "NOX"],
  ["usdc", "USDC"],
];
const unit = (c) => c.toUpperCase();

function menu(id, value, label) {
  const el = h(
    "select",
    { id, "aria-label": label },
    coins.map(([v, l]) => h("option", { value: v }, l)),
  );
  el.value = value;
  return el;
}

function form(p) {
  const from = menu("swap-from", p.from ?? "eth", "Coin you pay");
  const to = menu("swap-to", p.to ?? "nox", "Coin you receive");
  const amount = h("input", {
    id: "swap-amount",
    inputmode: "decimal",
    placeholder: "0",
    "aria-label": "Amount you pay",
    class: "swap-amount",
  });
  amount.value = p.amount ?? "";
  const slippage = h(
    "select",
    { id: "slippage" },
    [50, 100, 300].map((bps) => h("option", { value: String(bps) }, `${bps / 100}%`)),
  );
  slippage.value = String(p.slippage ?? 50);
  const keep = () => ({
    from: from.value,
    to: to.value,
    amount: amount.value.trim(),
    slippage: Number(slippage.value),
  });
  const flip = () => app.show("swap", { ...keep(), from: to.value, to: from.value, entered: true });
  const max = () =>
    app.run(async () => {
      amount.value = await app.call("publicMax", app.network, from.value);
    });
  const review = () =>
    app.run(async () => {
      const k = keep();
      if (!k.amount || k.from === k.to) return;
      const r = await app.call(
        "reviewPublicSwap",
        app.network,
        k.from,
        k.to,
        k.amount,
        String(k.slippage),
      );
      app.show("swap", { ...k, review: r, entered: true });
    });
  return {
    body: [
      h(
        "section",
        { class: "tile swap-box", "aria-label": "You pay" },
        h("p", { class: "swap-title" }, "You pay"),
        h(
          "div",
          { class: "swap-line" },
          amount,
          h("button", { type: "button", class: "swap-max", onclick: max }, "Max"),
          from,
        ),
      ),
      h(
        "div",
        { class: "swap-flip" },
        h("button", { type: "button", class: "flip", "aria-label": "Flip", onclick: flip }, "⇅"),
      ),
      h(
        "section",
        { class: "tile swap-box", "aria-label": "You receive" },
        h("p", { class: "swap-title" }, "You receive"),
        h("div", { class: "swap-line" }, h("span", { class: "lead" }, "Quoted on review"), to),
      ),
      h("div", { class: "field" }, h("label", { for: "slippage" }, "Max slippage"), slippage),
    ],
    footer: [button("Review swap", review, { busy: "Reading the pools" })],
  };
}

function review(p) {
  const s = p.review;
  const change = button(
    "Change it",
    () => app.show("swap", { ...p, review: null, entered: true }),
    { kind: "outline" },
  );
  if (s.refusal) return { body: [h("p", { class: "statement" }, s.refusal)], footer: [change] };
  const active = `Account ${(app.accounts?.find((a) => a.active)?.index ?? 0) + 1}`;
  const confirm = () =>
    app.run(async () => {
      await confirmed(app);
      const sent = await app.call("confirmPublicSend", s.id);
      app.show("swap", {
        ...p,
        review: null,
        sent,
        approval: s.approval,
        network: s.network,
        entered: true,
      });
    });
  return {
    body: [
      s.approval &&
        h(
          "p",
          { class: "statement" },
          `First, let Uniswap take exactly ${s.amountIn} ${unit(s.from)}. Then review the swap again.`,
        ),
      h(
        "section",
        { class: "tile", "aria-label": "The swap" },
        coinRow(s.from, s.amountIn, `${active} pays`),
        coinRow(s.to, `≈ ${s.expectedOut}`, "You receive"),
      ),
      swapTerms(s),
    ],
    footer: [
      button(s.approval ? "Confirm approval" : "Confirm swap", confirm, { busy: "Sending" }),
      change,
    ],
  };
}

/** Swapping between ETH, NOX and USDC on mainnet, as the apps' sideload builds do. */
export function swap() {
  const p = app.params;
  let part;
  if (!app.swaps) {
    part = {
      body: [h("p", { class: "statement" }, "Swaps run on Ethereum mainnet, where the pools are.")],
      footer: [
        button("Switch to Ethereum", async () => {
          app.network = "mainnet";
          await app.store.setMeta("network", "mainnet");
          app.public = null;
          app.show("swap");
        }),
      ],
    };
  } else if (p.sent) part = swapSent(p);
  else if (p.review) part = review(p);
  else part = form(p);
  return frame(
    {
      number: "03",
      title: "Swap",
      backdrop: "send",
      back: () => app.show("overview"),
      footer: part.footer,
    },
    networkBanner(app.network),
    ...part.body,
  );
}

swap.enter = async () => {
  app.swaps = await app.call("networkHasSwaps", app.network).catch(() => false);
  app.accounts ??= await app.call("accounts").catch(() => null);
};
