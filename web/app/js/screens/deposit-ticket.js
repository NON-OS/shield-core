import { h } from "../ui/h.js";
import { button } from "../ui/button.js";
import { facts } from "../ui/facts.js";
import { valueBlock } from "../ui/value-block.js";
import { copyThenClear } from "../ui/copy.js";
import { app } from "../state/app.js";

const step = (name, to, data) =>
  h(
    "section",
    { class: "field", "aria-label": name },
    h("p", { class: "label" }, name),
    valueBlock(to),
    h(
      "div",
      { class: "pair" },
      button("Copy to", () => copyThenClear(to), { kind: "outline" }),
      button("Copy data", () => copyThenClear(data), { kind: "outline" }),
    ),
  );

/** What to send from another wallet: one step for ETH, an approval and the deposit for NOX. */
export function depositTicket({ ticket: t, coin }) {
  const unit = coin.toUpperCase();
  const done = [button("Done", () => app.show("shield"), { kind: "outline" })];
  if (t.refusal) return { body: [h("p", { class: "lead" }, t.refusal)], footer: done };
  const two = Boolean(t.approveTo);
  return {
    body: [
      facts([
        ["you send", `${t.amount} ${unit}`],
        ["pool fee", `${t.fee} ${unit}`],
        ["note holds", `${t.note} ${unit}`],
      ]),
      two ? step("1  Approve", t.approveTo, t.approveData) : null,
      step(two ? "2  Deposit" : "Deposit", t.depositTo, t.depositData),
      h(
        "p",
        { class: "lead" },
        two
          ? "Send both from that address, value zero. Then read the pool and the note appears once the deposit is in a block."
          : `Send it from that address with a value of ${t.amount} ETH. Then read the pool; the note appears once it is in a block.`,
      ),
    ],
    footer: done,
  };
}
