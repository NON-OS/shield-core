// Shown once, before a wallet is made or opened, and again from Settings: what this test release
// is, and what a web wallet has to trust that the apps do not.

import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";
import { button } from "../ui/button.js";
import { app } from "../state/app.js";

export function warning() {
  const point = (text) => h("p", {}, text);
  return frame(
    "00",
    "Before you start",
    h("p", { class: "statement" }, "This is a test release. Please read it once."),
    h(
      "section",
      { class: "warning", "aria-label": "What this release is" },
      point(
        "The shield runs on Sepolia, a test network, and its tokens have no value. The public account can also hold real funds on Ethereum mainnet, and the page says so wherever mainnet is chosen.",
      ),
      point("Nothing is audited: not this page, not the wallet core, not the pool."),
      point("Use a fresh wallet for testing, never one that has held real money."),
    ),
    h(
      "section",
      { class: "warning", "aria-label": "What a web wallet trusts" },
      point(
        "This page is only as honest as the files it is served. They come from shield.nonos.app through Cloudflare, which sees the IP address of everyone who loads them. A changed file could read this wallet. Each release publishes the hash of every file, and Settings shows how to check what was served.",
      ),
      point(
        "A browser cannot use Tor. Every request goes from your IP address to the public endpoint that answers it, which learns that address and what was asked. For IP privacy, open this page in Tor Browser.",
      ),
      point(
        "Keys stay in this browser, sealed under a passkey. No key, note or seed is sent to any server, and there is no NØNOS server to send them to.",
      ),
      point(
        "A private send is proved here and needs about 1 GiB of memory. A phone browser may not give a page that much, so on a phone private sends wait until one test proof has finished here. If it cannot finish, use the NØNOS app or a computer. Nothing is ever proved on a server.",
      ),
    ),
    h(
      "div",
      { class: "actions" },
      button("I understand", async () => {
        await app.store.setMeta("warned", true);
        app.show(app.params.back ?? "welcome");
      }),
    ),
  );
}
