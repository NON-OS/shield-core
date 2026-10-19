import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { button } from "../ui/button.js";
import { field } from "../ui/field.js";
import { networkBanner } from "../ui/network-banner.js";
import { app } from "../state/app.js";
import { cannotProve } from "../text/cannot-prove.js";
import { proving } from "./spend-proving.js";
import { early } from "./spend-early.js";
import { ticket } from "./spend-ticket.js";

const hint = {
  eth: "Amount in ETH: 0.01, 0.02, 0.05, 0.1 and so on",
  nox: "Amount in NOX: 1,000, 2,000, 5,000, 10,000 and so on",
};

function refused(why) {
  return [
    h("p", { class: "statement" }, why.line),
    h("p", { class: "lead" }, why.lead),
    h(
      "div",
      { class: "actions" },
      why.measure && button("Time a test proof", () => app.show("measure")),
      button("Back", () => app.show("shield"), { kind: "outline" }),
    ),
  ];
}

function form(p) {
  const withdraw = p.withdraw;
  const coin = h(
    "select",
    { id: "coin" },
    h("option", { value: "nox" }, "NOX"),
    h("option", { value: "eth" }, "ETH"),
  );
  coin.value = p.coin ?? "nox";
  coin.addEventListener("change", () => app.show("spend", { ...p, coin: coin.value }));
  const to = field(withdraw ? "To EVM address" : "To wallet address", { value: p.to ?? "" });
  const amount = field(hint[coin.value], { inputmode: "decimal", value: p.amount ?? "" });
  if (withdraw && !p.to) {
    app.call("freshWithdrawalAddress").then((a) => {
      if (a && !to.input.value) {
        to.input.value = a;
        p.to = a;
        p.fresh = true;
      }
    });
  }
  const fee = withdraw
    ? h(
        "p",
        { class: "muted" },
        "Fee: 0.50% of the amount and a network part, paid from the shield.",
      )
    : h(
        "p",
        { class: "muted" },
        "Fee from the relay part, the same for everyone, with a network part that follows gas, paid from the shield.",
      );
  if (!withdraw) {
    app.call("relayFee", coin.value).then((f) => {
      fee.textContent = `Fee from ${f} ${coin.value.toUpperCase()}, the same for everyone, with a network part that follows gas, paid from the shield.`;
    });
  }
  const prove = () =>
    app.show("spend", {
      ...p,
      coin: coin.value,
      to: to.input.value.trim(),
      amount: amount.input.value.trim(),
      proving: true,
      early: false,
    });
  return [
    h(
      "p",
      { class: "lead" },
      "The proof hides who paid whom and how much. Deposits and withdrawals are public standard amounts.",
    ),
    h("div", { class: "field" }, h("label", { for: "coin" }, "Coin"), coin),
    to,
    withdraw &&
      h(
        "p",
        { class: "muted" },
        p.fresh
          ? "A fresh address of this wallet, never used. The words restore it as the next account."
          : "A withdrawal is public: its amount and the address it pays can be seen by anyone.",
      ),
    amount,
    fee,
    h(
      "div",
      { class: "actions" },
      button("Prove and seal", prove),
      button("Back", () => app.show("shield"), { kind: "outline" }),
    ),
  ];
}

export function spend() {
  const p = app.params;
  const title = p.withdraw ? "Withdraw" : "Send";
  const why =
    cannotProve(app.proving) ?? (app.cacheReady ? null : cannotProve({ state: "unable" }));
  let body;
  if (p.ticket) body = ticket(p);
  else if (why) body = refused(why);
  else if (p.tooSoon) body = early(p);
  else if (p.proving) body = proving(p);
  else body = form(p);
  return frame("03", title, networkBanner("sepolia"), body);
}
