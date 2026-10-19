import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { button } from "../ui/button.js";
import { field } from "../ui/field.js";
import { facts } from "../ui/facts.js";
import { networkBanner } from "../ui/network-banner.js";
import { app } from "../state/app.js";
import { confirmed } from "../device/confirmed.js";
import { untilMined } from "../state/poll.js";

const units = { eth: "ETH", nox: "NOX", usdc: "USDC" };

function form() {
  const coin = h(
    "select",
    { id: "coin" },
    Object.entries(units).map(([v, l]) => h("option", { value: v }, l)),
  );
  coin.value = app.params.coin ?? "nox";
  const to = field("To 0x address", { value: app.params.to ?? "" });
  const amount = field(`Amount in ${units[coin.value]}`, {
    value: app.params.amount ?? "",
    inputmode: "decimal",
  });
  coin.addEventListener("change", () =>
    app.show("accountSend", { ...app.params, coin: coin.value }),
  );
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
  return [
    h("div", { class: "field" }, h("label", { for: "coin" }, "Coin"), coin),
    to,
    amount,
    h("button", { type: "button", class: "link", onclick: max }, "Max"),
    h("div", { class: "actions" }, button("Review", review, { busy: "Working it out" })),
  ];
}

function review(r) {
  if (r.refusal) {
    return [
      h("p", { class: "statement" }, r.refusal),
      button("Change it", () => app.show("accountSend")),
    ];
  }
  const unit = units[r.coin];
  const send = () =>
    app.run(async () => {
      await confirmed(app);
      const sent = await app.call("confirmPublicSend", r.id);
      app.show("accountSend", { sent, network: r.network });
    });
  return [
    h("p", { class: "muted" }, "To"),
    h("p", { class: "address" }, r.to),
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
        { class: "warning" },
        `The recipient is a contract. Make sure it accepts ${unit}, or what is sent may be stuck there.`,
      ),
    h(
      "div",
      { class: "actions" },
      button("Confirm and send", send, { busy: "Sending" }),
      button("Change it", () => app.show("accountSend"), { kind: "outline" }),
    ),
  ];
}

function sent({ sent, network, status = "pending" }) {
  const line = {
    pending: "Sent. Waiting for a block.",
    confirmed: "Sent and mined.",
    failed: "Mined, but it failed. Nothing moved except the network fee.",
  }[status];
  if (status === "pending" && !app.params.polling) {
    app.params.polling = true;
    untilMined(app, network, sent.hash, (s) => {
      if (app.screen === "accountSend" && app.params.sent === sent && s !== status) {
        app.show("accountSend", { sent, network, status: s, polling: true });
      }
    });
  }
  return [
    h("p", { class: "statement", role: "status" }, line),
    h("p", { class: "muted" }, "Transaction"),
    h("p", { class: "address" }, sent.hash),
    h(
      "a",
      { href: sent.link, rel: "noreferrer noopener", target: "_blank" },
      "Open in the explorer",
    ),
    h(
      "div",
      { class: "actions" },
      button("Done", () => app.show("overview")),
    ),
  ];
}

export function accountSend() {
  const p = app.params;
  return frame(
    "03",
    "Send",
    networkBanner(p.review?.network ?? p.network ?? app.network),
    p.sent ? sent(p) : p.review ? review(p.review) : form(),
    !p.sent &&
      h("button", { type: "button", class: "link", onclick: () => app.show("overview") }, "Back"),
  );
}
