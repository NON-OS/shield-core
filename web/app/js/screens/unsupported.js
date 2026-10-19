import { h } from "../ui/h.js";
import { frame } from "../ui/frame.js";

/** The browser cannot seal a wallet behind a passkey, so the page makes and opens none. */
export function unsupported() {
  return frame(
    { number: "01", title: "NØNOS", backdrop: "welcome" },
    h("p", { class: "statement" }, "This browser cannot seal a wallet behind a passkey."),
    h(
      "p",
      { class: "lead" },
      "The wallet's key is sealed under a passkey with the PRF extension: a current Chrome or Edge, or Safari 18 or later, with the passkey on this device or in its password manager. The NØNOS app keeps the key in the phone's secure hardware instead. Nothing was stored here.",
    ),
  );
}
