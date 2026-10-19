import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { button } from "../ui/button.js";
import { facts } from "../ui/facts.js";
import { qr } from "../ui/qr/qr.js";
import { copyThenClear } from "../ui/copy.js";
import { app } from "../state/app.js";

export function receive() {
  const address = app.params.address ?? "";
  if (!address) {
    app.call("receivingAddress").then(
      (a) => app.show("receive", { address: a }),
      (e) => app.fail(e),
    );
  }
  return frame(
    "03",
    "Receive",
    h(
      "p",
      { class: "lead" },
      "Give this to the sender. It says nothing about the balance or the notes held.",
    ),
    address && qr(address, "QR code of the wallet address"),
    h("p", { class: "address" }, address),
    facts([
      ["sealed with", "X-Wing, X25519 + ML-KEM-768"],
      ["clipboard", "cleared after a minute"],
    ]),
    h(
      "div",
      { class: "actions" },
      button("Copy address", () => copyThenClear(address), { busy: "Copied" }),
      button("Receive at the 0x address", () => app.show("accountReceive"), { kind: "outline" }),
      button("Back", () => app.show("shield"), { kind: "outline" }),
    ),
  );
}
