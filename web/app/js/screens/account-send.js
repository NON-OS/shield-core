import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { button } from "../ui/button.js";
import { field } from "../ui/field.js";
import { facts } from "../ui/facts.js";
import { valueBlock } from "../ui/value-block.js";
import { networkBanner } from "../ui/network-banner.js";
import { copyThenClear } from "../ui/copy.js";
import { app } from "../state/app.js";
import { confirmed } from "../device/confirmed.js";
import { untilMined } from "../state/poll.js";

const units = { eth: "ETH", nox: "NOX", usdc: "USDC" };
const chain = (n) => (n === "mainnet" ? "Ethereum" : "Sepolia");

function form(p) {
  const coin = h(
    "select",
    { id: "coin" },
    Object.entries(units).map(([v, l]) => h("option", { value: v }, l)),
  );
  coin.value = p.coin ?? "nox";
  const to = field("To 0x address", { value: p.to ?? "" });
  const amount = field(`Amount in ${units[coin.value]}`, {
    value: p.amount ?? "",
    inputmode: "decimal",
  });
  coin.addEventListener("change", () => app.show("accountSend", { coin: coin.value }));
  const held = app.public?.network === app.network ? app.public[coin.value] : null;
  const review = () =>
    app.run(async () => {
      const r = await app.call(
        "reviewPublicSend",
        app.network,
        coin.value,
        to.input.value.trim(),
        amount.input.value.trim(),
      );
      app.show("accountSend", { review: r });
    });
  const max = () =>
    app.run(async () => {
      amount.input.value = await app.call("publicMax", app.network, coin.value);
    });
  return {
    body: [
      h("div", { class: "field" }, h("label", { for: "coin" }, "Coin"), coin),
      to,
      amount,
      held != null &&
        h(
          "p",
          { class: "lead" },
          `This account holds ${held} ${units[coin.value]} on ${chain(app.network)}.`,
        ),
      h("button", { type: "button", class: "quiet", onclick: max }, "Max"),
    ],
    footer: [button("Review", review, { busy: "Working it out" })],
  };
}

function review(r) {
  if (r.refusal) {
    return {
      body: [h("p", { class: "statement" }, r.refusal)],
      footer: [button("Change it", () => app.show("accountSend"), { kind: "outline" })],
    };
  }
  const unit = units[r.coin];
  const send = () =>
    app.run(async () => {
      await confirmed(app);
      const sent = await app.call("confirmPublicSend", r.id);
      app.show("accountSend", { sent, network: r.network });
    });
  return {
    body: [
      h("p", { class: "label" }, "To"),
      valueBlock(r.to),
      facts([
        ["from", r.from],
        ["you send", `${r.amount} ${unit}`],
        ["arrives", `${r.arrives} ${unit}`],
        r.coin === "nox" && ["token fee", `${r.tokenFee} NOX, ${r.tokenFeePercent}%`],
        ["network fee, at most", `${r.maxNetworkFee} ETH`],
        ["gas", `${r.gasLimit} at ${r.maxFeePerGasGwei} gwei`],
        ["nonce", String(r.nonce)],
        ["chain", String(r.chainId)],
      ]),
      r.toIsContract &&
        h(
          "p",
          { class: "lead" },
          `The recipient is a contract. Make sure it accepts ${unit}, or what is sent may be stuck there.`,
        ),
    ],
    footer: [
      button("Confirm and send", send, { busy: "Sending" }),
      button("Change it", () => app.show("accountSend"), { kind: "outline" }),
    ],
  };
}

function sent(p) {
  const status = p.status ?? "pending";
  const line = {
    pending: "Sent. Waiting for a block.",
    confirmed: "Sent and mined.",
    failed: "Mined, but it failed. Nothing moved except the network fee.",
  }[status];
  if (status === "pending" && !p.polling) {
    p.polling = true;
    untilMined(app, p.network, p.sent.hash, (s) => {
      if (app.screen === "accountSend" && app.params.sent === p.sent && s !== status) {
        app.show("accountSend", { ...p, status: s });
      }
    });
  }
  return {
    body: [
      h("p", { class: "statement", role: "status" }, line),
      h("p", { class: "label" }, "Transaction"),
      valueBlock(p.sent.hash),
      h(
        "div",
        { class: "pair" },
        button("Copy hash", () => copyThenClear(p.sent.hash), { kind: "outline" }),
        button("Copy link", () => copyThenClear(p.sent.link), { kind: "outline" }),
      ),
    ],
    footer: [button("Done", () => app.show("overview"))],
  };
}

export function accountSend() {
  const p = app.params;
  const part = p.sent ? sent(p) : p.review ? review(p.review) : form(p);
  return frame(
    {
      number: "03",
      title: "Send",
      backdrop: "send",
      back: p.sent ? null : () => app.show("overview"),
      footer: part.footer,
    },
    networkBanner(p.review?.network ?? p.network ?? app.network),
    ...part.body,
  );
}
