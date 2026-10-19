import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";

/** The browser cannot seal a wallet behind a passkey, so the page makes and opens none. */
export function unsupported() {
  return frame(
    "01",
    "This browser cannot hold the wallet",
    h(
      "p",
      { class: "statement" },
      "The wallet's key has to be sealed under a passkey, and this browser cannot do that.",
    ),
    h(
      "p",
      { class: "lead" },
      "A passkey with the PRF extension is needed: a current Chrome or Edge, or Safari 18 or later, with a passkey saved on the device or in its password manager. The NØNOS app keeps the key in the phone's secure hardware instead. Nothing was stored here.",
    ),
  );
}
