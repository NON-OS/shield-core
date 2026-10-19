// Shown once, before a wallet is made or opened, and again from Settings: what this test release
// is, and what a web wallet has to trust that the apps do not.

import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { button } from "../ui/button.js";
import { app } from "../state/app.js";

export function warning() {
  const lead = (text) => h("p", { class: "lead" }, text);
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
    lead(
      "The shield runs on Sepolia only, and its tokens have no value. The public account moves real funds on Ethereum mainnet. Nothing is audited: not this page, not the core, not the pool. Use a fresh wallet for testing, never one that has held real money.",
    ),
    h("p", { class: "label" }, "What the web version trusts"),
    lead(
      "This page is only as honest as the files it is served. They come from shield.nonos.app through Cloudflare, which sees the IP address of everyone who loads them. A changed file could read this wallet. Every release publishes the hash of each file, and Settings shows how to check what was served.",
    ),
    lead(
      "A browser cannot use Tor, so the wallet's requests go through the Nym mixnet. The RPC providers and transaction relays that answer its reads and sends see a Nym exit, not your IP address. The Nym gateway they enter by sees your IP address, not what was asked or of whom. Each request takes a few seconds longer. If Nym cannot be reached, the page asks before it connects directly, and you can turn Nym off in Settings until the page is closed.",
    ),
    lead(
      "Nym does not hide everything. Cloudflare still sees your IP address when it serves this page, and what happens on chain is public, as always.",
    ),
    lead(
      "The key is sealed under a passkey, where the apps use the Secure Enclave or the Keystore. No key, note or seed is sent to any server.",
    ),
    lead(
      "A deposit's note is kept only in this browser's storage until it is spent, as on the phones, and the recovery words do not bring an unspent deposit back. A browser can clear a site's storage: Safari does after seven days without a visit, unless the page is on the home screen. Add it to the home screen, and after a deposit use Make it recoverable, a private send to this wallet's own address, whose notes the words do restore.",
    ),
    lead(
      "A proof needs about 1 GiB of memory. A phone browser may not give a page that much, so on a phone private sends wait until one test proof has finished here. If it cannot finish, use the NØNOS app or a computer. Nothing is ever proved on a server.",
    ),
  );
}
