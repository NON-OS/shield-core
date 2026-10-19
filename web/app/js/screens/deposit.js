import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { button } from "../ui/button.js";
import { field } from "../ui/field.js";
import { facts } from "../ui/facts.js";
import { networkBanner } from "../ui/network-banner.js";
import { app } from "../state/app.js";
import { confirmed } from "../device/confirmed.js";
import { untilMined } from "../state/poll.js";

const hint = {
  eth: "Amount in ETH: 0.01, 0.02, 0.05 and so on",
  nox: "Amount in NOX: 1,000, 2,000, 5,000 and so on",
};

function form() {
  const coin = h(
    "select",
    { id: "coin" },
    h("option", { value: "nox" }, "NOX"),
    h("option", { value: "eth" }, "ETH"),
  );
  coin.value = app.params.coin ?? "nox";
  coin.addEventListener("change", () => app.show("deposit", { coin: coin.value }));
  const amount = field(hint[coin.value], { inputmode: "decimal" });
  const review = () =>
    app.run(async () => {
      const r = await app.call("reviewShield", coin.value, amount.input.value.trim());
      app.show("deposit", { coin: coin.value, amount: amount.input.value.trim(), review: r });
    });
  return [
    h(
      "p",
      { class: "lead" },
      "From your public account, signed here. The pool is checked first, and nothing is sent if it would refuse.",
    ),
    h("div", { class: "field" }, h("label", { for: "coin" }, "Coin"), coin),
    amount,
    h("div", { class: "actions" }, button("Review", review, { busy: "Reading the pool" })),
  ];
}

function review({ review: r, coin, amount }) {
  const unit = coin.toUpperCase();
  if (r.refusal) {
    return [
      h("p", { class: "statement" }, r.refusal),
      button("Change it", () => app.show("deposit", { coin })),
    ];
  }
  const send = () =>
    app.run(async () => {
      await confirmed(app);
      const sent = await app.call("confirmPublicSend", r.id);
      app.show("deposit", { coin, amount, sent, approval: r.approval });
    });
  return [
    r.approval &&
      h(
        "p",
        { class: "statement" },
        `First, let the pool take exactly ${r.amount} ${unit}. Then the deposit.`,
      ),
    facts([
      ["you shield", `${r.amount} ${unit}`],
      ["pool fee", `${r.poolFee} ${unit}`],
      ["the note holds", `${r.shielded} ${unit}`],
      ["network fee, at most", `${r.maxNetworkFee} ETH`],
    ]),
    h(
      "div",
      { class: "actions" },
      button(r.approval ? "Confirm approval" : "Confirm and shield", send, { busy: "Sending" }),
      button("Change it", () => app.show("deposit", { coin }), { kind: "outline" }),
    ),
  ];
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
  return [
    h("p", { class: "statement", role: "status" }, line),
    h("p", { class: "address" }, p.sent.hash),
    status === "confirmed" &&
      !p.approval &&
      h(
        "p",
        { class: "lead" },
        "The note is in the pool. A private send waits for 20 more notes and about six hours after it, which the meter on the shield counts down.",
      ),
    h(
      "div",
      { class: "actions" },
      status === "confirmed" && p.approval
        ? button("Review the deposit", () =>
            app.run(async () => {
              const r = await app.call("reviewShield", p.coin, p.amount);
              app.show("deposit", { coin: p.coin, amount: p.amount, review: r });
            }),
          )
        : button("Done", () => app.show("shield")),
    ),
  ];
}

export function deposit() {
  const p = app.params;
  return frame(
    "03",
    "Deposit",
    networkBanner("sepolia"),
    p.sent ? sent(p) : p.review ? review(p) : form(),
    !p.sent &&
      h("button", { type: "button", class: "link", onclick: () => app.show("shield") }, "Back"),
  );
}
