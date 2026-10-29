import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { button } from "../ui/button.js";
import { field } from "../ui/field.js";
import { amountField } from "../ui/amount-field.js";
import { networkBanner } from "../ui/network-banner.js";
import { app } from "../state/app.js";
import { cannotProve } from "../text/cannot-prove.js";
import { proving } from "./spend-proving.js";
import { early } from "./spend-early.js";
import { ticket } from "./spend-ticket.js";
import { notes } from "./spend-notes.js";

function refused(why) {
  return {
    body: [h("p", { class: "statement" }, why.line), h("p", { class: "lead" }, why.lead)],
    footer: [why.measure && button("Time a test proof", () => app.show("measure"))].filter(Boolean),
  };
}

// Why a send to this wallet's own address, and what it costs: the time of a proof here and the
// network fee of settling it, since the pool's fee comes back to the account that settles.
const recoverable = (state) =>
  `A send to this wallet's own address. Its notes are sealed to the recovery words, so a restore on another device finds them. The proof runs in this browser, ${state?.measured ? `about ${Math.round(state.measured.seconds)} s as timed here` : "about 75 s on a four-core computer"}. Settling it from your public account costs the network fee, shown before you confirm, and the pool's fee comes back to that account.`;

function form(p) {
  const withdraw = p.withdraw;
  const coin = h(
    "select",
    { id: "coin" },
    h("option", { value: "nox" }, "NOX"),
    h("option", { value: "eth" }, "ETH"),
  );
  coin.value = p.coin ?? "nox";
  coin.addEventListener("change", () =>
    app.show("spend", { ...p, coin: coin.value, entered: true }),
  );
  const to = field(withdraw ? "To EVM address" : "To wallet address", { value: p.to ?? "" });
  const amount = amountField(coin.value, { value: p.amount ?? "" });
  const note = h("div", { class: "content-notes" });
  const update = () => notes(p, to.input.value.trim(), note);
  to.input.addEventListener("input", update);
  if (p.self && !p.to) {
    app.call("receivingAddress").then((a) => {
      p.to = a;
      if (a && !to.input.value) to.input.value = a;
      update();
    });
  } else if (withdraw && !p.to && p.fresh === undefined) {
    app.call("freshWithdrawalAddress").then((a) => {
      p.fresh = a;
      if (a && !to.input.value) to.input.value = a;
      update();
    });
  } else update();
  const fee = h(
    "p",
    { class: "lead" },
    withdraw ? "Fee: 0.50% of the amount and a network part, paid from the shield." : "",
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
      entered: true,
    });
  return {
    body: [
      h(
        "p",
        { class: "lead" },
        p.self
          ? recoverable(app.proving)
          : "The proof hides who paid whom and how much. Deposits and withdrawals are public standard amounts.",
      ),
      h("div", { class: "field" }, h("label", { for: "coin" }, "Coin"), coin),
      to,
      amount,
      note,
      fee,
    ],
    footer: [button("Prove and seal", prove)],
  };
}

export function spend() {
  const p = app.params;
  const why =
    cannotProve(app.proving) ?? (app.cacheReady ? null : cannotProve({ state: "unable" }));
  let part;
  if (p.ticket) part = ticket(p);
  else if (why) part = refused(why);
  else if (p.tooSoon) part = early(p);
  else if (p.proving) part = proving(p);
  else part = form(p);
  const busy = p.proving && !p.ticket;
  return frame(
    {
      number: "03",
      title: p.withdraw ? "Withdraw" : "Send",
      backdrop: p.withdraw ? "withdraw" : "send",
      back: busy ? null : () => app.show("shield"),
      footer: part.footer,
    },
    networkBanner("sepolia"),
    ...part.body,
  );
}

spend.enter = async () => {
  app.accounts ??= await app.call("accounts").catch(() => null);
};
