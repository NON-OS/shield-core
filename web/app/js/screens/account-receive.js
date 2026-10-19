import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { button } from "../ui/button.js";
import { facts } from "../ui/facts.js";
import { qr } from "../ui/qr/qr.js";
import { networkBanner } from "../ui/network-banner.js";
import { copyThenClear } from "../ui/copy.js";
import { app } from "../state/app.js";

export function accountReceive() {
  const address = app.params.address ?? "";
  if (!address) {
    app.call("publicAddress").then(
      (a) => app.show("accountReceive", { address: a }),
      (e) => app.fail(e),
    );
  }
  return frame(
    "03",
    "Receive",
    networkBanner(app.network),
    h("p", { class: "lead" }, "Public: anyone can see what this address holds and sends."),
    address && qr(address, "QR code of the 0x address"),
    h("p", { class: "address" }, address),
    facts([
      ["networks", "Ethereum and Sepolia, one address"],
      ["derived at", "m/44'/60'/0'/0/0"],
    ]),
    h(
      "div",
      { class: "actions" },
      button("Copy address", () => copyThenClear(address), { busy: "Copied" }),
      button("Back", () => app.show("overview"), { kind: "outline" }),
    ),
  );
}
