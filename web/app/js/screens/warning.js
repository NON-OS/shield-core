// Shown once, before a wallet is made or opened, and again from Settings: what this test release
// is, and what a web wallet has to trust that the apps do not. The four facts stay in sight; each
// trust is a heading that opens to its full account, so the screen fits a phone without hiding any.

import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { button } from "../ui/button.js";
import { app } from "../state/app.js";

const facts = [
  "The shield runs on Sepolia only, and its tokens have no value.",
  "The public account moves real funds on Ethereum mainnet.",
  "Nothing is audited: not this page, not the core, not the pool.",
  "Use a fresh wallet for testing, never one that has held real money.",
];

const trusts = [
  [
    "Your IP address",
    "Hidden by the Nym mixnet",
    "Every read and send leaves through the Nym mixnet. The RPC providers and relays that answer see a Nym exit, never your IP address, and the gateway you enter by sees your address but not what you asked or of whom. If Nym cannot be reached, the page asks before it connects directly.",
  ],
  [
    "Your key",
    "Sealed under a passkey",
    "The key is sealed under a passkey, where the apps use the Secure Enclave or the Keystore. No key, note or seed is sent to any server.",
  ],
  [
    "Your proofs",
    "Made on this device",
    "Every proof is made here, never on a server. A proof needs about 1 GiB of memory; a phone browser may not give a page that much, so on a phone private sends wait until one test proof has finished. If it cannot finish, use the NØNOS app or a computer.",
  ],
  [
    "Your deposits",
    "Kept in this browser",
    "A deposit's note stays in this browser until it is spent, and the recovery words do not bring an unspent deposit back. Safari clears a site's storage after seven days without a visit unless the page is on the home screen. Add it to the home screen, and after a deposit use Make it recoverable, a private send to your own address, whose notes the words do restore.",
  ],
  [
    "This page",
    "Checkable, file by file",
    "Every release publishes the hash of each file, and Settings shows how to check exactly what you were served. Like any website, loading the page shows your IP address to its host; the NØNOS apps, which connect over Tor, avoid even that.",
  ],
];

export function warning() {
  const back = app.params.back;
  return frame(
    {
      number: "00",
      title: "Before you start",
      backdrop: "welcome",
      back: back === "settings" ? () => app.show("settings") : null,
      footer: [
        button("I understand", async () => {
          await app.store.setMeta("warned", true);
          app.show(back ?? "welcome");
        }),
      ],
    },
    h("p", { class: "statement" }, "This is a test release, on a test network."),
    h(
      "ul",
      { class: "warning-facts" },
      facts.map((text) => h("li", {}, text)),
    ),
    h("p", { class: "label" }, "What the web version trusts"),
    h(
      "div",
      { class: "trusts" },
      trusts.map(([name, short, ...body]) =>
        h(
          "details",
          { class: "trust" },
          h(
            "summary",
            {},
            h("span", { class: "trust-name" }, name),
            h("span", { class: "trust-short" }, short),
          ),
          body.map((text) => h("p", { class: "lead" }, text)),
        ),
      ),
    ),
  );
}
