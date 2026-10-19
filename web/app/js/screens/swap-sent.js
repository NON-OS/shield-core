import { h } from "../ui/h.js";
import { button } from "../ui/button.js";
import { valueBlock } from "../ui/value-block.js";
import { copyThenClear } from "../ui/copy.js";
import { app } from "../state/app.js";
import { untilMined } from "../state/poll.js";

/** A sent swap or approval, followed to its block. After an approval the form opens again. */
export function swapSent(p) {
  const status = p.status ?? "pending";
  if (status === "pending" && !p.polling) {
    p.polling = true;
    untilMined(app, p.network, p.sent.hash, (s) => {
      if (app.screen === "swap" && app.params.sent === p.sent && s !== "pending")
        app.show("swap", { ...p, status: s });
    });
  }
  const line = {
    pending: "Sent. Waiting for a block.",
    confirmed: "Sent and mined.",
    failed: "Mined, but it failed. Nothing moved except the network fee.",
  }[status];
  const done = () =>
    p.approval
      ? app.show("swap", { from: p.from, to: p.to, amount: p.amount, slippage: p.slippage })
      : app.show("overview");
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
    footer: [button("Done", done)],
  };
}
