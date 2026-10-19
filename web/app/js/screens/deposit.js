import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { button } from "../ui/button.js";
import { field } from "../ui/field.js";
import { facts } from "../ui/facts.js";
import { quiet } from "../ui/quiet.js";
import { valueBlock } from "../ui/value-block.js";
import { networkBanner } from "../ui/network-banner.js";
import { copyThenClear } from "../ui/copy.js";
import { app } from "../state/app.js";
import { confirmed } from "../device/confirmed.js";
import { untilMined } from "../state/poll.js";
import { short } from "../text/short.js";
import { depositTicket } from "./deposit-ticket.js";

const sizes = {
  eth: "Amount in ETH: 0.01, 0.02, 0.05 and so on",
  nox: "Amount in NOX: 1,000, 2,000, 5,000 and so on",
};

const picker = (p, screen = "deposit") => {
  const coin = h(
    "select",
    { id: "coin" },
    h("option", { value: "nox" }, "NOX"),
    h("option", { value: "eth" }, "ETH"),
  );
  coin.value = p.coin ?? "nox";
  coin.addEventListener("change", () =>
    app.show(screen, { ...p, coin: coin.value, entered: true }),
  );
  return { coin, el: h("div", { class: "field" }, h("label", { for: "coin" }, "Coin"), coin) };
};

const active = () => {
  const a = app.accounts?.find((x) => x.active);
  return `Account ${(a?.index ?? 0) + 1}`;
};

function form(p) {
  const { coin, el } = picker(p);
  const amount = field(sizes[coin.value], { inputmode: "decimal" });
  const review = () =>
    app.run(async () => {
      const r = await app.call("reviewShield", coin.value, amount.input.value.trim());
      app.show("deposit", { coin: coin.value, amount: amount.input.value.trim(), review: r });
    });
  return {
    body: [
      h(
        "p",
        { class: "lead" },
        `From ${active()}, signed here. The pool is checked first, and nothing is sent if it would refuse.`,
      ),
      el,
      amount,
      quiet([
        [
          "Deposit from another wallet instead",
          () => app.show("deposit", { coin: coin.value, external: true }),
        ],
      ]),
    ],
    footer: [button("Review", review, { busy: "Reading the pool" })],
  };
}

function external(p) {
  const { coin, el } = picker(p);
  const from = field("From EVM address", {
    value: p.from ?? app.accounts?.find((x) => x.active)?.publicAddress ?? "",
  });
  const amount = field(`Amount in ${coin.value.toUpperCase()}`, { inputmode: "decimal" });
  const check = () =>
    app.run(async () => {
      const t = await app.call(
        "prepareDeposit",
        coin.value,
        amount.input.value.trim(),
        from.input.value.trim(),
      );
      app.show("deposit", { coin: coin.value, ticket: t });
    });
  return {
    body: [
      h(
        "p",
        { class: "lead" },
        "The EVM address you will send from, and how much. The pool is checked first, and nothing is kept if it would refuse.",
      ),
      el,
      from,
      amount,
    ],
    footer: [button("Check the pool", check, { busy: "Reading the pool" })],
  };
}

function review({ review: r, coin, amount }) {
  const unit = coin.toUpperCase();
  if (r.refusal) {
    return {
      body: [h("p", { class: "statement" }, r.refusal)],
      footer: [button("Change it", () => app.show("deposit", { coin }), { kind: "outline" })],
    };
  }
  const send = () =>
    app.run(async () => {
      await confirmed(app);
      const sent = await app.call("confirmPublicSend", r.id);
      app.show("deposit", { coin, amount, sent, approval: r.approval });
    });
  const from = app.accounts?.find((x) => x.active);
  return {
    body: [
      r.approval &&
        h(
          "p",
          { class: "statement" },
          `First, let the pool take exactly ${r.amount} ${unit}. Then the deposit.`,
        ),
      facts([
        ["from", from ? `${active()}, ${short(from.publicAddress)}` : active()],
        ["you shield", `${r.amount} ${unit}`],
        ["pool fee", `${r.poolFee} ${unit}`],
        ["the note holds", `${r.shielded} ${unit}`],
        ["network fee, at most", `${r.maxNetworkFee} ETH`],
      ]),
    ],
    footer: [
      button(r.approval ? "Confirm approval" : "Confirm and shield", send, { busy: "Sending" }),
      button("Change it", () => app.show("deposit", { coin }), { kind: "outline" }),
    ],
  };
}

function sent(p) {
  const status = p.status ?? "pending";
  const line =
    status === "failed"
      ? "Mined, but it failed. Nothing moved except the network fee."
      : status === "pending"
        ? p.approval
          ? "Approval sent. Waiting for a block."
          : "Deposit sent. Waiting for a block."
        : p.approval
          ? "The pool may take it now."
          : "Shielded.";
  if (status === "pending" && !p.polling) {
    p.polling = true;
    untilMined(app, "sepolia", p.sent.hash, (s) => {
      if (app.screen === "deposit" && app.params.sent === p.sent && s !== "pending") {
        app.show("deposit", { ...p, status: s });
      }
    });
  }
  const done = status === "confirmed";
  return {
    body: [
      h("p", { class: "statement", role: "status" }, line),
      h("p", { class: "label" }, "Transaction"),
      valueBlock(p.sent.hash),
      button("Copy link", () => copyThenClear(p.sent.link), { kind: "outline" }),
      done &&
        !p.approval &&
        h(
          "p",
          { class: "lead" },
          "The note is in the pool. A private send waits for 20 more notes and about six hours after it, which the meter on the shield counts down.",
        ),
    ],
    footer: [
      done && p.approval
        ? button("Review the deposit", () =>
            app.run(async () => {
              const r = await app.call("reviewShield", p.coin, p.amount);
              app.show("deposit", { coin: p.coin, amount: p.amount, review: r });
            }),
          )
        : button("Done", () => app.show("shield")),
    ],
  };
}

export function deposit() {
  const p = app.params;
  const part = p.sent
    ? sent(p)
    : p.ticket
      ? depositTicket(p)
      : p.review
        ? review(p)
        : p.external
          ? external(p)
          : form(p);
  return frame(
    {
      number: "03",
      title: "Deposit",
      backdrop: "deposit",
      back: p.sent
        ? null
        : () =>
            app.show(
              p.external || p.ticket ? "deposit" : "shield",
              p.external || p.ticket ? { coin: p.coin } : {},
            ),
      footer: part.footer,
    },
    networkBanner("sepolia"),
    ...part.body,
  );
}

deposit.enter = async () => {
  app.accounts ??= await app.call("accounts").catch(() => null);
};
